//
// Created by gaelin on 9/23/24.
//

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include "tcp_scanner.h"


#define SQL_HOST "127.0.0.1"
#define SQL_USER "cyber"
#define SQL_PASS ""
#define SQL_DB "findv2"

#define TO_SCAN_QUERY "SELECT id, net, mask FROM ranges WHERE owner = '' ORDER BY scans, scan_time ASC"

//#define SRC_IP_ADDRESS ""
#define SRC_IP_ADDRESS "10.3.2.15"
#define SRC_PORT 1025
#define TCP_SCAN_PORTS 80, 443, 8080, 8000


unsigned const short SCAN_PORTS[] = {TCP_SCAN_PORTS, 0};
FILE *f;


struct netmask {
    unsigned int net;
    unsigned short mask;
    unsigned int last;
};

struct {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
} sql;

void open_callback(struct response_t *resp) {
    print_resp(resp);

    fprintf(
            f,
            "%d.%d.%d.%d:%d\n",
            resp->ip.ip_src.s_addr & 0xff,
            resp->ip.ip_src.s_addr >> 8 & 0xff,
            resp->ip.ip_src.s_addr >> 16 & 0xff,
            resp->ip.ip_src.s_addr >> 24,
            htons(resp->tcp.th_sport));
}

void sql_init() {
    // Initialize MySQL connection
    if ((sql.conn = mysql_init(NULL)) == NULL) {
        exit_critical_error("mysql_init");
    }

    // Connect to the database
    if (mysql_real_connect(sql.conn, SQL_HOST, SQL_USER, SQL_PASS, SQL_DB, 0, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(sql.conn));
        mysql_close(sql.conn);
        exit_critical_error("mysql_real_connect");
    }
}

void sql_query(const char *query) {

    // Execute the query
    if (mysql_query(sql.conn, query)) {
        fprintf(stderr, "SELECT query failed: %s\n", mysql_error(sql.conn));
        mysql_close(sql.conn);
        exit_critical_error("mysql_query");
    }

    // Store result
    if ((sql.res = mysql_store_result(sql.conn)) == NULL) {
        fprintf(stderr, "mysql_store_result() failed: %s\n", mysql_error(sql.conn));
        mysql_close(sql.conn);
        exit_critical_error("mysql_store_result");
    }
}

void sql_cleanup() {
    mysql_free_result(sql.res);
    mysql_close(sql.conn);
}

int main(int argc, char *argv[]) {

//    if (argc < 2) { printf("%s <source ip> ")}

    struct scanner_t scanner = {};
    scanner.callback = open_callback;

    start_socket_listen(&scanner, SRC_IP_ADDRESS, SRC_PORT, SCAN_PORTS);

    sql_init();
    sql_query(TO_SCAN_QUERY);


    f = fopen("out/c.out", "a");


    // Fetch and print result rows
    while ((sql.row = mysql_fetch_row(sql.res)) != NULL) {
        unsigned int id = atoi(sql.row[0]);
        unsigned int net = atoi(sql.row[1]);
        unsigned short mask = atoi(sql.row[2]);
        net = 167969280; // 10.3.2.0
        mask = 24;

        printf(
                "id: %d, net: %d.%d.%d.%d/%d\n",
                id,
                net >> 24 & 0xff,
                net >> 16 & 0xff,
                net >> 8 & 0xff,
                net & 0xff,
                mask
        ); // edianness is wrong here


        struct netmask target = {net, mask, net | ~((0xFFFFFFFFUL << (32 - mask)) & 0xFFFFFFFFUL)};

        for (const unsigned short *port = SCAN_PORTS; *port != 0; port++) {
            for (unsigned int ip = target.net; ip < target.last; ip++) {
                unsigned int a = htonl(ip);
//                printf("Host: ");
//                print_ip(a);
//                printf(" Port: %d (%d)\n", *port, id);

                send_syn(&scanner, a, *port);
            }
        }
        break;
    }

//    sleep(10);


    sql_cleanup();

    shutdown_listen_thread(&scanner);
    fclose(f);

    return EXIT_SUCCESS;
}
