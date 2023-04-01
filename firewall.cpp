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

enum HOSTS {
    HOST_INVALID = -1,
    HOST_EXT,
    HOST_FIREWALL,
    HOST_INFECTED,
    HOST_INT
};

static const char ADDRS[][16] = {
    "192.168.1.11", "192.168.1.12", "192.168.1.12", "192.168.1.10"};
static const int PORTS[]            = {9091, 9091, 9090, 9090};

static const u_int32_t INET_ADDRS[] = {
    inet_addr(ADDRS[HOST_EXT]), inet_addr(ADDRS[HOST_FIREWALL]),
    inet_addr(ADDRS[HOST_INFECTED]), inet_addr(ADDRS[HOST_INT])};
static const u_int16_t INET_PORTS[] = {
    htons(PORTS[HOST_EXT]), htons(PORTS[HOST_FIREWALL]),
    htons(PORTS[HOST_INFECTED]), htons(PORTS[HOST_INT])};

static const __uint16_t udph_len = sizeof(struct udphdr);
static const __uint16_t iph_len  = sizeof(struct iphdr);
static const __uint16_t headers_len =
    sizeof(struct iphdr) + sizeof(struct udphdr);

static const auto MAX_PKT_LENTH        = 65535;
static __uint8_t buffer[MAX_PKT_LENTH] = {0};

static struct iphdr* iph               = (struct iphdr*)buffer;
static struct udphdr* udph             = (struct udphdr*)(buffer + iph_len);

static const double cloning_prob       = 0.01;
static const int RAND_SEED             = 100;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        perror("Invalid argument count.");
        exit(1);
    }

    auto seed = RAND_SEED == 0 ? 1 : RAND_SEED;
    srand(seed);

    auto sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket error: ");
        exit(3);
    }

    int one        = 1;
    const int* val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error: ");
        exit(4);
    }

    sockaddr_in dest_addr     = {0};
    socklen_t dest_addrlen    = sizeof(dest_addr);
    dest_addr.sin_family      = AF_INET;
    dest_addr.sin_addr.s_addr = INET_ADDRS[HOST_EXT];

    sockaddr_in server        = {0};
    socklen_t server_size     = sizeof(server);

    int method                = atoi(argv[1]);
    std::cout << method << std::endl;

    while (1) {
        auto valread = recvfrom(
            sock, buffer, MAX_PKT_LENTH, 0, (struct sockaddr*)&server,
            &server_size
        );
        if (valread <= 0) break;

        if (udph->dest != INET_PORTS[HOST_FIREWALL] || iph->protocol != 17)
            continue;

        udph->dest = INET_PORTS[HOST_EXT];
        iph->daddr = INET_ADDRS[HOST_EXT];

        switch (method) {
            case 1:
                iph->tos = 0x20;  // 00100000
                iph->ttl = 0x40;  // 64
                break;
            case 2:
                if ((rand() % 101) <= (cloning_prob * 100))
                    if (sendto(
                            sock, buffer, ntohs(iph->tot_len), 0,
                            (struct sockaddr*)&dest_addr, dest_addrlen
                        ) < 0) {
                        perror("sendto() error: ");
                        exit(3);
                    }
                break;
            case 0:
                break;
        }

        if (sendto(
                sock, buffer, ntohs(iph->tot_len), 0,
                (struct sockaddr*)&dest_addr, dest_addrlen
            ) < 0) {
            perror("sendto() error: ");
            exit(3);
        }
    }
    shutdown(sock, SHUT_RDWR);
    return 0;
}