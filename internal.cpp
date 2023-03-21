#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <termios.h>
#include <unistd.h>

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
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

static const char ADDRS[][16] = {
    "192.168.1.11", "192.168.1.11", "192.168.1.12", "192.168.1.10"};
static const int PORTS[]            = {9091, 9090, 9090, 9090};

static const u_int32_t INET_ADDRS[] = {
    inet_addr(ADDRS[HOST_COVERT_CHANNEL]), inet_addr(ADDRS[HOST_EXT]),
    inet_addr(ADDRS[HOST_PROXY]), inet_addr(ADDRS[HOST_INT])};
static const u_int16_t INET_PORTS[] = {
    htons(PORTS[HOST_COVERT_CHANNEL]), htons(PORTS[HOST_EXT]),
    htons(PORTS[HOST_PROXY]), htons(PORTS[HOST_INT])};

static const auto RAND_SEED           = 125;
static const auto THREADS_SIZE        = 16;
// В милисекундах
static const auto SLEEP_TIME          = 0;

static const __uint32_t MAX_PKT_LENTH = 65535;
enum RANGES { R_MIN = 0, R_MAX };
static const __uint16_t PAYLOAD_LEN[] = {64, 1024};
static const __uint16_t ID_VAL[]      = {1024, 65535};
static const __uint16_t TTL_VAL[]     = {32, 80};

static const __uint16_t udph_len      = sizeof(struct udphdr);
static const __uint16_t iph_len       = sizeof(struct iphdr);
static const __uint16_t headers_len =
    sizeof(struct iphdr) + sizeof(struct udphdr);

__uint8_t buffer[MAX_PKT_LENTH] = {0};
iphdr *iph                      = (struct iphdr *)buffer;
udphdr *udph                    = (struct udphdr *)(buffer + iph_len);

static __uint16_t IPChecksum(__uint16_t *addr, __uint32_t nwords) {
    __uint64_t sum(0);
    for (; nwords > 0; nwords -= 2) sum += *addr++;
    if (nwords > 0) sum += ((*addr) & htons(0xFF00));
    // Круговой перенос
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (__uint16_t)~sum;
}

// Вычисление checksum с учетом псевдозаголовка IPv4
static void UDPChecksum(struct iphdr *pIphdr, __uint16_t *ipPayload) {
    __uint64_t sum(0);
    struct udphdr *udp = (struct udphdr *)(ipPayload);
    __uint16_t udp_len = htons(udp->len);
    // Добавляем псевдозаголовок к контрольной сумме
    sum += (pIphdr->saddr >> 16) & 0xFFFF;
    sum += (pIphdr->saddr) & 0xFFFF;
    sum += (pIphdr->daddr >> 16) & 0xFFFF;
    sum += (pIphdr->daddr) & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udp->len;
    // Добавляем поля самого UDP
    udp->check = 0;
    for (; udp_len > 1; udp_len -= 2) sum += *ipPayload++;
    if (udp_len > 0) sum += ((*ipPayload) & htons(0xFFFF));
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    sum        = ~sum;
    udp->check = ((__uint16_t)sum == 0x0000) ? 0xFFFF : (__uint16_t)sum;
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

int main(int argc, char *argv[]) {
    auto sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket error: ");
        exit(1);
    }

    int one        = 1;
    const int *val = &one;
    // Выставляем флаг для сокета на уровне IP на IP_HDRINCL, т.е. что
    // будем формировать пакет начиная с IP (IP + UDP + Data) сами
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error: ");
        exit(2);
    }

    // Генерируем различные информационные потоки: first - адрес источника,
    // second - значение ttl для данного потока
    std::vector<std::pair<in_addr_t, __uint8_t>> threads;

    for (int i = 0; i < THREADS_SIZE; ++i) {
        std::string address;
        for (int j = 0; j < 4; ++j)
            address += std::to_string(1 + rand() % 254) += j != 3 ? '.' : ' ';
        threads.push_back(std::make_pair(
            inet_addr(address.c_str()),
            TTL_VAL[R_MIN] + rand() % (TTL_VAL[R_MAX] - TTL_VAL[R_MIN] + 1)
        ));
    }

    // Пересылать пакет будем ручками на адрес прокси
    struct sockaddr_in proxy_addr;
    const socklen_t proxy_addrlen(sizeof(proxy_addr));
    proxy_addr.sin_family      = AF_INET;
    proxy_addr.sin_addr.s_addr = INET_ADDRS[HOST_PROXY];
    proxy_addr.sin_port        = INET_PORTS[HOST_PROXY];

    srand(RAND_SEED == 0 ? time(NULL) : RAND_SEED);

    HEADLINE("Start of UDP fluding.\n");
    while (!kbhit()) {
        __uint16_t payload_len =
            PAYLOAD_LEN[R_MIN] +
            rand() % (PAYLOAD_LEN[R_MAX] - PAYLOAD_LEN[R_MIN] + 1);

        // Определяем поток
        const auto thread = threads[rand() % THREADS_SIZE];
        // Формируем IP заголовок
        iph->ihl          = 5;
        iph->version      = 4;
        iph->tos          = 16;
        iph->tot_len      = headers_len + payload_len;
        iph->id =
            htons(ID_VAL[R_MIN] + rand() % (ID_VAL[R_MIN] - ID_VAL[R_MAX] + 1));
        iph->ttl      = thread.second;
        iph->protocol = 17;  // UDP
        // Симулируем различные информационные потоки
        iph->saddr    = thread.first;
        iph->daddr    = inet_addr("192.168.1.12");
        iph->check    = 0x1234;

        // Формируем UDP заголовок
        udph->source  = INET_PORTS[HOST_INT];
        udph->dest    = INET_PORTS[HOST_PROXY];
        udph->len     = htons(udph_len + payload_len);
        UDPChecksum(iph, (__uint16_t *)udph);

        // Добавляем данные (рандомный набор 8битных слов)
        for (auto i = 0; i < payload_len; ++i)
            buffer[headers_len + i] = __uint16_t(rand() % 256);

        if (sendto(
                sock, buffer, iph->tot_len, 0, (struct sockaddr *)&proxy_addr,
                proxy_addrlen
            ) < 0) {
            perror("sendto() error: ");
            exit(3);
        }
        std::cout << "\n\tA sended packet info:\n\tFrame size (without Ether "
                     "Header): "
                  << std::dec << headers_len + payload_len
                  << "\n\tIdentification: " << iph->id << "\n\tTTL:\t"
                  << __uint16_t(iph->ttl);
        std::cout << std::dec << "\n\tPayload: ";
        for (auto i{0}; i < payload_len; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << __uint16_t(buffer[headers_len + i]) << ' ';
        std::cout << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    }
    HEADLINE("End of UDP fluding.\n");
    close(sock);
    return 0;
}
