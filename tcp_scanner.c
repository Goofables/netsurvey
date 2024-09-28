//
// Created by gaelin on 8/19/24.
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

#include "tcp_scanner.h"

//struct scanner_t {
//    unsigned const short SCAN_PORTS[8];
//    unsigned long stats[8];
//    int stop;
//    struct sockaddr_in serv_addr;
//    int sock;
//};

struct response_t {
    struct ip ip;
    struct tcphdr tcp;
};

struct scanner_t {
    const unsigned short *ports;
    long long *stats;
    struct sockaddr_in serv_addr;
    int sock;

    void *(*callback)(struct response_t *);

    int active;
    pthread_t listen_thread;
};

int exit_critical_error(char *err) {
    perror(err);
    exit(1);
    return EXIT_FAILURE;
}


unsigned short checksum(unsigned short *buffer, size_t len) {
    unsigned int checksum = 0;
    for (; len > 1; len -= 2) checksum += *buffer++;
    if (len == 1) checksum += *(unsigned char *) buffer;
    checksum = (checksum >> 16) + (checksum & 0xFFFF); // 0x######## > 0x0001####
    checksum += (checksum >> 16); // 0x0001#### > 0x0000####
    return ~checksum;
}


void send_syn(struct scanner_t *scanner, const unsigned int dst_ip, const unsigned short dst_port) {

    struct sockaddr_in dst_addr_generic = {};
    dst_addr_generic.sin_family = AF_INET;
    dst_addr_generic.sin_addr.s_addr = 1;
    dst_addr_generic.sin_port = htons(dst_port);

    struct {
        struct ip ip;
        struct tcphdr tcp;
    } packet = {};

    packet.ip.ip_src.s_addr = scanner->serv_addr.sin_addr.s_addr;
    packet.ip.ip_dst.s_addr = dst_ip;
    packet.ip.ip_p = IPPROTO_TCP;
    packet.ip.ip_len = htons(20);

    packet.tcp.th_sport = scanner->serv_addr.sin_port;
    packet.tcp.th_dport = dst_addr_generic.sin_port;
    // packet.tcp.seq = 0;
    // packet.tcp.ack = 0;
    packet.tcp.th_off = 5;
    packet.tcp.th_flags = TH_SYN;
    packet.tcp.th_win = htons(8192);
    // packet.tcp.th_sum = 0;
    // packet.tcp.th_urp = 0;

    unsigned int tcp_chk = checksum((unsigned short *) &packet, sizeof(packet));

    packet.ip.ip_v = IPVERSION;
    packet.ip.ip_hl = 5;
    // packet.ip.ip_tos = 0;
    packet.ip.ip_id = htons(1);
    // packet.ip.ip_off = 0;
    packet.ip.ip_ttl = 64;
    packet.ip.ip_len = htons(40);
    // packet.ip.ip_sum = 0

    packet.tcp.th_sum = tcp_chk;

    unsigned int ip_chk = checksum((unsigned short *) &packet.ip, sizeof(packet.ip));

    packet.ip.ip_sum = ip_chk;

    // printf("Sending\n");
//    if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *) &dst_addr_generic, sizeof(dst_addr_generic)) < 0) {
//        printf(
//                "Failed to syn %d > %d.%d.%d.%d:%d\n",
//                htons(packet.tcp.th_sport),
//                packet.ip.ip_dst.s_addr & 0xff,
//                packet.ip.ip_dst.s_addr >> 8 & 0xff,
//                packet.ip.ip_dst.s_addr >> 16 & 0xff,
//                packet.ip.ip_dst.s_addr >> 24 & 0xff,
//                htons(packet.tcp.th_dport));
//        sleep(1);
//    }

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


void *listen_loop(struct scanner_t *scanner) {
    struct response_t resp;
    while (scanner->active) {
        // printf("Recv wait\n");
        if (recv(scanner->sock, &resp, sizeof(resp), 0) < 0) {
            perror("recv");
        }

        if (resp.tcp.th_flags != (TH_SYN | TH_ACK)) continue;
        // printf("%d.%d.%d.%d > %d.%d.%d.%d : %d > %d  s:%d a:%d\n", resp.ip.ip_src.s_addr & 0xff,
        //        resp.ip.ip_src.s_addr >> 8 & 0xff, resp.ip.ip_src.s_addr >> 16 & 0xff, resp.ip.ip_src.s_addr >> 24,
        //        resp.ip.ip_dst.s_addr & 0xff, resp.ip.ip_dst.s_addr >> 8 & 0xff, resp.ip.ip_dst.s_addr >> 16 & 0xff,
        //        resp.ip.ip_dst.s_addr >> 24, htons(resp.tcp.th_sport), htons(resp.tcp.th_dport), resp.tcp.syn,
        //        resp.tcp.ack);
        unsigned short src_port = htons(resp.tcp.th_sport);
        for (unsigned short *p = scanner->ports; *p != 0; p++) {
            if (*p == src_port) {
                scanner->callback(&resp);
                break;
            }
        }
    }
    return NULL;
}


void start_socket_listen(struct scanner_t *scanner, const char *src_ip, const unsigned short *ports) {
    int size = 0;
    for (; ports[size] != 0; size++);
    scanner->stats = malloc(size * sizeof(long long));
    scanner->ports = ports;
    scanner->active = 1;
    // Setup source address
    scanner->serv_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, src_ip, &scanner->serv_addr.sin_addr) <= 0) {
        perror("pton");
    }

    // Prep socket
    if ((scanner->sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("init");
    }

    // Set no auto headers
    const int one = 1;
    if (setsockopt(scanner->sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
    }

    // Bind to any
    scanner->serv_addr.sin_port = 0;
    if (bind(scanner->sock, (struct sockaddr *) &scanner->serv_addr, sizeof(scanner->serv_addr)) < 0) {
        perror("bind");
    }

    // Get bound port
    socklen_t addr_len = sizeof(scanner->serv_addr);
    getsockname(scanner->sock, (struct sockaddr *) &scanner->serv_addr, &addr_len);
    printf(
            "Bound to: %d.%d.%d.%d:%d\n",
            scanner->serv_addr.sin_addr.s_addr & 0xff,
            scanner->serv_addr.sin_addr.s_addr >> 8 & 0xff,
            scanner->serv_addr.sin_addr.s_addr >> 16 & 0xff,
            scanner->serv_addr.sin_addr.s_addr >> 24 & 0xff,
            htons(scanner->serv_addr.sin_port));

    // Dont listen because raw socket
    // if (listen(sock, 256 * 256) < 0)
    //     critical_error("listen");
    // printf("Listening\n");

    if (pthread_create(&scanner->listen_thread, NULL, listen_loop, scanner) != 0) {
        exit_critical_error("Error with pthread! Could not start listener!\n");
    }
}


void shutdown_listen_thread(struct scanner_t *scanner) {
    scanner->active = 0;
    // printf("After: %d\n", data_out[256 * 256 * 256 * 10 + 1]);

    pthread_join(scanner->listen_thread, NULL);
}

//void send_syn_all_optimized(unsigned const short d_port, struct scanner_t *scan) {
//
//    struct sockaddr_in dst_addr_generic = {};
//    dst_addr_generic.sin_family = AF_INET;
//    dst_addr_generic.sin_addr.s_addr = 1;
//    dst_addr_generic.sin_port = htons(d_port);
//
//    struct {
//        struct ip ip;
//        struct tcphdr tcp;
//    } packet = {};
//
//    packet.ip.ip_src.s_addr = s_addr;
//    packet.ip.ip_dst.s_addr = 0;
//    packet.ip.ip_p = IPPROTO_TCP;
//    packet.ip.ip_len = htons(20);
//
//    packet.tcp.th_sport = s_port;
//    packet.tcp.th_dport = dst_addr_generic.sin_port;
//    //    packet.tcp.seq = 0;
//    //    packet.tcp.ack = 0;
//    packet.tcp.th_off = 5;
//    packet.tcp.th_flags = TH_SYN;
//    packet.tcp.th_win = htons(8192);
//    //    packet.tcp.th_sum = 0;
//    //    packet.tcp.th_urp = 0;
//
//    unsigned int tcp_chk = checksum((unsigned short *) &packet, sizeof(packet));
//
//    packet.ip.ip_v = IPVERSION;
//    packet.ip.ip_hl = 5;
//    //    packet.ip.ip_tos = 0;
//    packet.ip.ip_id = htons(1);
//    //    packet.ip.ip_off = 0;
//    packet.ip.ip_ttl = 64;
//    packet.ip.ip_len = htons(40);
//    //    packet.ip.ip_sum = 0
//
//    unsigned int ip_chk = checksum((unsigned short *) &packet.ip, sizeof(packet.ip));
//    unsigned int tmp, tmp_chk;
//    for (
//            unsigned int i = 1; i > 0; i++
//            ) {
//        // unsigned int i = 256 * 256 * 256 + 10;
//        if ((i & 0xff) == 127) continue;
//        if ((i & 0xff) >= 224) continue;
//        // if ((i & 0xffff) != 10) continue;
//
//        tmp = (i >> 16) + (i & 0xffff);
//        tmp = (tmp >> 16) + (tmp & 0xffff);
//
//        tmp_chk = tcp_chk - tmp;
//        packet.tcp.th_sum = (tmp_chk >> 16) + tmp_chk & 0xffff;
//
//        tmp_chk = ip_chk - tmp;
//        packet.ip.ip_sum = (tmp_chk >> 16) + tmp_chk & 0xffff;
//
//        packet.ip.ip_dst.s_addr = i;
//
//        // printf("Sending\n");
//        if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *) &dst_addr_generic, sizeof(dst_addr_generic)) <
//            0) {
//            printf(
//                    "Attempted to syn %d > %d.%d.%d.%d:%d\n",
//                    htons(packet.tcp.th_sport),
//                    packet.ip.ip_dst.s_addr & 0xff,
//                    packet.ip.ip_dst.s_addr >> 8 & 0xff,
//                    packet.ip.ip_dst.s_addr >> 16 & 0xff,
//                    packet.ip.ip_dst.s_addr >> 24 & 0xff,
//                    htons(packet.tcp.th_dport));
//            sleep(1);
//            i -= 1;
//            continue;
//            exit_critical_error("send");
//
//        }
//    }
//
//    /*//// DEBUG:
//       packet.ip.ip_sum = ip_chk;
//       packet.tcp.th_sum = tcp_chk;
//       printf("TCP: ");
//       print_hex(packet.tcp.th_sum >> 8);
//       print_hex(packet.tcp.th_sum);
//       printf(" bd13\n IP: ");
//       print_hex(packet.ip.ip_sum >> 8);
//       print_hex(packet.ip.ip_sum);
//       printf(" fffe\nall: ");
//       print_hex(checksum((unsigned short *) &packet, sizeof(packet)) >> 8);
//       print_hex(checksum((unsigned short *) &packet, sizeof(packet)));
//       printf(" ea7b\n");
//    // */
//}