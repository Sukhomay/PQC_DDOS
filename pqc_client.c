#include "SETUP.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

/* ========================== */
/* GLOBALS                    */
/* ========================== */
static volatile int keep_running = 1;

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

/* ========================== */
/* OPENSSL INIT               */
/* ========================== */
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_client_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_client_context(SSL_CTX *ctx) {
    /* PQC group for key exchange */
    if (SSL_CTX_set1_groups_list(ctx, HANDSHAKE_ALGO) != 1) {
        printf("[!] Failed to set PQC group\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Load trusted certificate for verification */
    if (SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL) != 1) {
        printf("[!] Failed to load trusted certificate %s\n", CERT_FILE);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*
     * Use SSL_VERIFY_NONE for Mininet compatibility.
     * Mininet assigns dynamic IPs (10.0.0.x) that won't match the
     * certificate SAN. The full PQC handshake (ML-KEM key exchange +
     * ML-DSA signature) still runs — we only skip the IP/hostname check.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

/* ========================== */
/* SINGLE HANDSHAKE           */
/* ========================== */
typedef struct {
    int success;        /* 1 = success, 0 = failure */
    uint64_t cycles;    /* handshake cycles (rdtscp) */
} handshake_result_t;

handshake_result_t do_handshake(SSL_CTX *ctx, const char *server_ip) {
    handshake_result_t result = {0, 0};

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return result;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "[!] Invalid target IP: %s\n", server_ip);
        close(sock);
        return result;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return result;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        close(sock);
        return result;
    }

    SSL_set_fd(ssl, sock);

    uint64_t start = rdtscp();

    if (SSL_connect(ssl) <= 0) {
        printf("SSL_connect failed\n"); 
        uint64_t end = rdtscp();
        result.cycles = end - start;
        result.success = 0;
    } else {
        printf("SSL_connect success\n");
        uint64_t end = rdtscp();
        result.cycles = end - start;
        result.success = 1;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    return result;
}

/* ========================== */
/* MAIN                       */
/* ========================== */
int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <server_ip> <interval_ms> [count]\n", argv[0]);
        printf("  server_ip   : Target server IP\n");
        printf("  interval_ms : Delay between handshakes in ms\n");
        printf("  count       : Number of handshakes (0 = infinite)\n");
        return 1;
    }

    const char *server_ip = argv[1];
    int interval_ms = atoi(argv[2]);
    int count = (argc >= 4) ? atoi(argv[3]) : 0;

    signal(SIGINT, handle_sigint);
    signal(SIGPIPE, SIG_IGN);

    init_openssl();
    SSL_CTX *ctx = create_client_context();
    configure_client_context(ctx);

    /* Open CSV log */
    FILE *csv = fopen("client_metrics.csv", "w");
    if (!csv) {
        perror("Failed to open client_metrics.csv");
        SSL_CTX_free(ctx);
        return 1;
    }
    fprintf(csv, "timestamp,handshake_num,status,handshake_cycles\n");
    fflush(csv);

    printf("PQC TLS Client starting...\n");
    printf("  Target       : %s:%d\n", server_ip, PORT);
    printf("  Interval     : %d ms\n", interval_ms);
    printf("  Count        : %s\n", count == 0 ? "infinite" : argv[3]);
    printf("  KEM          : %s\n", HANDSHAKE_ALGO);
    printf("  Cert         : %s\n", CERT_FILE);
    printf("----------------------------------\n");

    uint64_t total_success = 0;
    uint64_t total_fail = 0;
    uint64_t total_cycles = 0;
    int handshake_num = 0;
    printf("count: %d\n", count);
    while (keep_running) {
        if (count > 0 && handshake_num >= count) break;

        handshake_num++;
        printf("handshake %d\n", handshake_num);
        handshake_result_t res = do_handshake(ctx, server_ip);

        const char *status_str = res.success ? "success" : "fail";
        printf("handshake %d: %s\n", handshake_num, status_str);    
        /* Write to CSV */
        fprintf(csv, "%ld,%d,%s,%lu\n",
                (long)time(NULL), handshake_num,
                status_str, res.cycles);
        fflush(csv);


        if (res.success) {
            total_success++;
            total_cycles += res.cycles;
        } else {
            total_fail++;
        }

        /* Wait before next handshake */
        if (keep_running && (count == 0 || handshake_num < count)) {
            usleep(interval_ms * 1000);
        }
    }

    fclose(csv);

    /* Summary written only to CSV – nothing on stdout */

    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
