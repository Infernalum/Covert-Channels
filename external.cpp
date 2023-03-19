#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
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
    INVALID_HOST = -1,
    COVERT_CHANNEL,
    EXT_HOST,
    PROXY_HOST,
    INT_HOST
};
enum RANGES { R_MIN, R_MAX };
enum METHODS { INVALID_METHOS = -1, TTL, QOS, CHECKSUM };

static const char ADDRS[][16] = {
    "192.168.1.11", "192.168.1.11", "192.168.1.12", "192.168.1.10"};
static const int PORTS[]            = {9091, 9090, 9090, 9090};

static const u_int32_t INET_ADDRS[] = {
    inet_addr(ADDRS[COVERT_CHANNEL]), inet_addr(ADDRS[EXT_HOST]),
    inet_addr(ADDRS[PROXY_HOST]), inet_addr(ADDRS[INT_HOST])};
static const u_int16_t INET_PORTS[] = {
    htons(PORTS[COVERT_CHANNEL]), htons(PORTS[EXT_HOST]),
    htons(PORTS[PROXY_HOST]), htons(PORTS[INT_HOST])};

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
static const __uint8_t FILE_SIZE = sizeof(size_type);
// Кол-во полученных фрагментов части файла; в зависимости от метода имеет
// размерность байта, бита, etc.
static size_type bytes_received  = 0;

static const char usage[] =
    "Usage: ./external "
    "<method>.\nMethods: \"QOS\", "
    "\"TTL\", \"CHECKSUM\"";
static const char sections[][10] = {"Filename", "File size", "File data"};
static const char stages[][40]   = {
    "Start of the ", " receiving.", " has been successfully received."};

METHODS paramValidation(const int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Invalid argument count.\n" << usage << std::endl;
        exit(1);
    }
    std::string arg(argv[1]);
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

static bool QOSImplementation(
    std::string& filename, __uint32_t& size, std::string& data
) {
    if (udph->dest != INET_PORTS[COVERT_CHANNEL]) return 0;
    const auto& byte = iph->tos;
    int is_finished  = TRANS_NOT;

    if (bytes_received == 0)
        std::cout << stages[0] << sections[in_progress] << stages[1]
                  << std::endl;

    switch (in_progress) {
        // Получаем имя файла
        case TRANS_FILENAME:
            filename.push_back(byte);
            std::cout << "Filename[" << bytes_received << "]:\t" << filename
                      << std::endl;
            if (++bytes_received == FILENAME_SIZE) {
                is_finished    = in_progress++;
                bytes_received = 0;
            }
            break;
        // Получаем размер файла
        case TRANS_FILESIZE:
            size = size | (byte << (bytes_received * 8));
            std::cout << std::setw(2) << std::setfill('0') << std::hex << "Hex["
                      << bytes_received << "]:\t\t" << size << std::dec
                      << std::endl;
            if (++bytes_received == FILE_SIZE) {
                is_finished    = in_progress++;
                bytes_received = 0;
                std::cout << "Total (dec):\t" << size << std::endl;
            }
            break;
        // Получаем содержимое файла
        case TRANS_DATA:
            data.push_back(byte);
            std::cout << std::setw(2) << std::setfill('0') << std::hex
                      << __uint16_t(byte) << ' ';
            if (++bytes_received == size) {
                std::cout << std::endl;
                is_finished    = in_progress++;
                bytes_received = 0;
            }
            break;
        default:
            std::cerr << "Invalid transmission status.\n";
            exit(2);
    }

    if (is_finished != TRANS_NOT)
        std::cout << std::endl
                  << sections[is_finished] << stages[2] << std::endl;

    return in_progress == TRANS_FINISHED ? 1 : 0;
}

static bool TTLImplementation(
    std::string& filename, __uint32_t& size, std::string& data
) {
    // Интервал в пакетах
    static const auto waiting_period = 10;
    static auto cur_pkt              = 0;
    static auto avarage_ttl          = 0;
    int is_finished                  = TRANS_NOT;
    static __uint8_t bit_ind;
    // Чтобы сразу пометился передаваемый размер
    static size_type buf;

    // Эмулируем работу сниффера
    if (udph->dest == INET_PORTS[EXT_HOST]) {
        // Определяем среднее значение ttl: оно будет ttl_min (декодирует как
        // 0), ttl_max = ttl_min + 1 (декодирует как 1)
        if (cur_pkt < waiting_period) {
            ++cur_pkt;
            std::cout << "Flows listening...\n";
            avarage_ttl += iph->ttl;
            return 0;
        }
        if (cur_pkt == waiting_period) {
            ++cur_pkt;
            avarage_ttl /= waiting_period;
            std::cout << "Average TTL field value: " << avarage_ttl
                      << std::endl;
            buf = 0x00;
            std::cout << "The Covert Channel has been activated.\n";
        }
        return 0;
    }

    if (bytes_received == 0 && bit_ind == 0) {
        std::cout << stages[0] << sections[in_progress] << stages[1]
                  << std::endl;
        bit_ind = 0;
    }

    __uint8_t bit = iph->ttl <= avarage_ttl ? 0x00 : 0x01;
    std::cout << (bool)bit;
    buf = buf | (bit << bit_ind++);

    switch (in_progress) {
        // Получаем имя файла
        case TRANS_FILENAME:
            if (bit_ind == 8) {
                // std::cout << std::endl;
                ++bytes_received;
                bit_ind = 0;
                filename.push_back((__uint8_t)buf);
                buf = 0x00;
                std::cout << "\t\tFilename[" << bytes_received << "]:\t"
                          << filename << std::endl;
            }
            if (bytes_received == FILENAME_SIZE) goto ttlL1;
            break;
        // Получаем размер
        case TRANS_FILESIZE:
            if (bit_ind == FILE_SIZE * 8) {
                // std::cout << std::endl;
                size = buf;
                buf  = 0x00;
                std::cout << "\t\tFilename size: " << size << std::endl;
                goto ttlL1;
            }
            break;
        // Получаем содержимое файла
        case TRANS_DATA:
            if (bit_ind == 8) {
                // std::cout << std::endl;
                data.push_back((__uint8_t)buf);
                buf     = 0x00;
                bit_ind = 0;
                ++bytes_received;
            }
            if (bytes_received == size) goto ttlL1;
            break;
        default:
            std::cerr << "Invalid transmission status.\n";
            exit(2);
    }

    if (false) {
    ttlL1:
        is_finished    = in_progress++;
        bytes_received = 0;
        bit_ind        = 0;
    }
    if (is_finished != TRANS_NOT)
        std::cout << std::endl
                  << sections[is_finished] << stages[2] << std::endl;

    return in_progress == TRANS_FINISHED ? 1 : 0;
}

static bool CHECKSUMImplementation(
    std::string& filename, __uint32_t& size, std::string& data
) {
    return 0;
}

typedef bool (*fn)(std::string&, __uint32_t&, std::string& data);
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
    // Выставляем флаг для сокета на уровне IP на IP_HDRINCL, чтобы получать
    // от карты всю полезную нагрузку IP + хедер
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error: ");
        exit(4);
    }

    std::string filename, data;
    size_type file_size(0x00);
    auto is_finished(false);
    HEADLINE("The Covert Channel has been activated.\n");
    in_progress = TRANS_FILENAME;
    while (!is_finished && !kbhit()) {
        auto valread = recvfrom(
            sock, buffer, MAX_PKT_LENTH, 0, (struct sockaddr*)&sender_addr,
            &sender_addrlen
        );
        if (valread <= 0) break;

        if ((udph->dest != INET_PORTS[COVERT_CHANNEL] &&
             udph->dest != INET_PORTS[EXT_HOST]) ||
            iph->protocol != 17 || iph->daddr != INET_ADDRS[EXT_HOST])
            continue;

        is_finished = implementations[method](filename, file_size, data);
    }
    HEADLINE("The Covert Channel is closed.\n");

    std::ofstream file(filename, std::ofstream::out | std::ofstream::trunc);
    if (!file.is_open()) {
        std::cerr << "Unable to open file.\n";
        exit(3);
    }
    file << data;
    file.close();
    shutdown(sock, SHUT_RDWR);
    return 0;
}