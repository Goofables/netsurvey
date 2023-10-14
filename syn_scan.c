//
// Created by goofables on 5/20/23.
//

#include <netinet/tcp.h>
#include <sys/socket.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/mman.h>

#define SRC_IP "#.#.#.#"

unsigned const short SCAN_PORTS[] = {22, 80, 443, 139, 445, 3389, 3306, 25565};
unsigned long stats[8] = {};
int sock;
struct sockaddr_in serv_addr = {};
int active = 1;
char *data_out;


void critical_error(char *err) {
    perror(err);
    exit(1);
}


void print_hex(unsigned char c) {
    char l[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    printf("%c%c", l[c >> 4], l[c & 0xf]);
}


unsigned short checksum(unsigned short *buffer, size_t len) {
    unsigned int checksum = 0;
    for (; len > 1; len -= 2) checksum += *buffer++;
    if (len == 1) checksum += *(unsigned char *) buffer;
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    return ~checksum;
}


void send_syn(unsigned short port) {

    struct sockaddr_in dst_addr_generic = {};
    dst_addr_generic.sin_family = AF_INET;
    dst_addr_generic.sin_addr.s_addr = 1;
    dst_addr_generic.sin_port = htons(port);

    struct {
        struct ip ip;
        struct tcphdr tcp;
    } packet = {};

    packet.ip.ip_src.s_addr = serv_addr.sin_addr.s_addr;
    packet.ip.ip_dst.s_addr = 0;
    packet.ip.ip_p = IPPROTO_TCP;
    packet.ip.ip_len = htons(20);

    packet.tcp.th_sport = serv_addr.sin_port;
    packet.tcp.th_dport = dst_addr_generic.sin_port;
    //    packet.tcp.seq = 0;
    //    packet.tcp.ack = 0;
    packet.tcp.th_off = 5;
    packet.tcp.th_flags = TH_SYN;
    packet.tcp.th_win = htons(8192);
    //    packet.tcp.th_sum = 0;
    //    packet.tcp.th_urp = 0;

    unsigned int tcp_chk = checksum((unsigned short *) &packet, sizeof(packet));

    packet.ip.ip_v = IPVERSION;
    packet.ip.ip_hl = 5;
    //    packet.ip.ip_tos = 0;
    packet.ip.ip_id = htons(1);
    //    packet.ip.ip_off = 0;
    packet.ip.ip_ttl = 64;
    packet.ip.ip_len = htons(40);
    //    packet.ip.ip_sum = 0

    unsigned int ip_chk = checksum((unsigned short *) &packet.ip, sizeof(packet.ip));
    unsigned int tmp, tmp_chk;
    for (unsigned int i = 1; i > 0; i++) {
        // unsigned int i = 256 * 256 * 256 + 10;
        if ((i & 0xff) == 127) continue;
        if ((i & 0xff) >= 224) continue;
        // if ((i & 0xffff) != 10) continue;

        tmp = (i >> 16) + (i & 0xffff);
        tmp = (tmp >> 16) + (tmp & 0xffff);

        tmp_chk = tcp_chk - tmp;
        packet.tcp.th_sum = (tmp_chk >> 16) + tmp_chk & 0xffff;

        tmp_chk = ip_chk - tmp;
        packet.ip.ip_sum = (tmp_chk >> 16) + tmp_chk & 0xffff;

        packet.ip.ip_dst.s_addr = i;

        // printf("Sending\n");
        if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *) &dst_addr_generic, sizeof(dst_addr_generic)) <
            0) {
            printf(
                "Attempted to syn %d > %d.%d.%d.%d:%d\n",
                htons(packet.tcp.th_sport),
                packet.ip.ip_dst.s_addr & 0xff,
                packet.ip.ip_dst.s_addr >> 8 & 0xff,
                packet.ip.ip_dst.s_addr >> 16 & 0xff,
                packet.ip.ip_dst.s_addr >> 24 & 0xff,
                htons(packet.tcp.th_dport));
            sleep(1);
            i -= 1;
            continue;
            critical_error("send");

        }
    }

/*    //// DEBUG:
       packet.ip.ip_sum = ip_chk;
       packet.tcp.th_sum = tcp_chk;
       printf("TCP: ");
       print_hex(packet.tcp.th_sum >> 8);
       print_hex(packet.tcp.th_sum);
       printf(" bd13\n IP: ");
       print_hex(packet.ip.ip_sum >> 8);
       print_hex(packet.ip.ip_sum);
       printf(" fffe\nall: ");
       print_hex(checksum((unsigned short *) &packet, sizeof(packet)) >> 8);
       print_hex(checksum((unsigned short *) &packet, sizeof(packet)));
       printf(" ea7b\n");
    // */
}

void *listen_loop(void *_) {
    struct {
        struct ip ip;
        struct tcphdr tcp;
    } resp = {};
    while (active) {
        // printf("Recv wait\n");
        if (recv(sock, &resp, sizeof(resp), 0) < 0) {
            critical_error("recv");
        }

        if (resp.tcp.th_flags != (TH_SYN | TH_ACK)) continue;
        // printf("%d.%d.%d.%d > %d.%d.%d.%d : %d > %d  s:%d a:%d\n", resp.ip.ip_src.s_addr & 0xff,
        //        resp.ip.ip_src.s_addr >> 8 & 0xff, resp.ip.ip_src.s_addr >> 16 & 0xff, resp.ip.ip_src.s_addr >> 24,
        //        resp.ip.ip_dst.s_addr & 0xff, resp.ip.ip_dst.s_addr >> 8 & 0xff, resp.ip.ip_dst.s_addr >> 16 & 0xff,
        //        resp.ip.ip_dst.s_addr >> 24, htons(resp.tcp.th_sport), htons(resp.tcp.th_dport), resp.tcp.syn,
        //        resp.tcp.ack);
        unsigned short src_port = htons(resp.tcp.th_sport);
        for (int p = 0; p < 8; p++) {
            if (SCAN_PORTS[p] == src_port) {
                // printf("Host: %d.%d.%d.%d Port: %d bin: %d\n", resp.ip.ip_src.s_addr & 0xff,
                //        resp.ip.ip_src.s_addr >> 8 & 0xff, resp.ip.ip_src.s_addr >> 16 & 0xff,
                //        resp.ip.ip_src.s_addr >> 24 & 0xff, src_port, 1 << p);
                data_out[htonl(resp.ip.ip_src.s_addr)] |= 1 << p;
                stats[p]++;
                break;
            }
        }
    }
    return NULL;
}

void setup_socket() {
    // Setup source address
    serv_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, SRC_IP, &serv_addr.sin_addr) <= 0) {
        critical_error("pton");
    }

    // Prep socket
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        critical_error("init");
    }

    // Set no auto headers
    const int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        critical_error("setsockopt");
    }

    // Bind to any
    serv_addr.sin_port = 0;
    if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        critical_error("bind");
    }

    // Get bound port
    socklen_t addr_len = sizeof(serv_addr);
    getsockname(sock, (struct sockaddr *) &serv_addr, &addr_len);
    printf(
        "Bound to: %d.%d.%d.%d:%d\n",
        serv_addr.sin_addr.s_addr & 0xff,
        serv_addr.sin_addr.s_addr >> 8 & 0xff,
        serv_addr.sin_addr.s_addr >> 16 & 0xff,
        serv_addr.sin_addr.s_addr >> 24 & 0xff,
        htons(serv_addr.sin_port)
    );

    // Dont listen because raw socket
    // if (listen(sock, 256 * 256) < 0)
    //     critical_error("listen");
    // printf("Listening\n");
}

void setup_file_mmap() {
    // open fiile for a+b a+ = append/create b = binary (b probably not necessary)
    FILE *fd = fopen("scan_data.bin", "a+b");

    // Truncate to exactly 256^4
    int fno = fileno(fd);
    ftruncate(fno, (unsigned int) UINT32_MAX);

    // map to memory
    if ((data_out = mmap(NULL, UINT32_MAX, PROT_READ | PROT_WRITE, MAP_SHARED, fno, 0)) == MAP_FAILED) {
        critical_error("mmap");
    }
    // Cleanup unused fd
    fclose(fd);
}

int main() {
    pthread_t listen_thread;

    setup_socket();
    setup_file_mmap();

    // printf("Before: %d\n", data_out[256 * 256 * 256 * 10 + 1]);

    if (pthread_create(&listen_thread, NULL, listen_loop, NULL) != 0) {
        printf("Error with pthread! Could not start listener!\n");
        exit(1);
    }

    // exit(69);
    // Scan each port
    // for (int i = 0; i < 8; i++) {
    int i = 1;
    // Timing
    struct timeval stop, start;
    gettimeofday(&start, NULL);

    // Actual scan command
    printf("Scanning port %d...\n", SCAN_PORTS[i]);
    send_syn(SCAN_PORTS[i]);

    // Timing
    gettimeofday(&stop, NULL);
    printf(
        "Total %lds (%luus)\n",
        (stop.tv_sec - start.tv_sec),
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec
    );
    // }

    // Wait for callbacks
    printf("Waiting for callbacks\n");
    sleep(15);
    active = 0;
    // printf("After: %d\n", data_out[256 * 256 * 256 * 10 + 1]);

    pthread_join(listen_thread, NULL);

    if (munmap(data_out, UINT32_MAX) != 0) {
        critical_error("munmap");
    }

    // Shutdown socket
    printf("Shutting down\n");
    if (close(sock) < 0) {
        critical_error("close");
    }
    for (int p = 0; p < 8; p++) {
        printf("Port %d total %lu\n", SCAN_PORTS[p], stats[p]);
    }

    return 0;
}