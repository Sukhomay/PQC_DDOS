#include "SETUP.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

/* ========================== */
/* GLOBAL METRICS */
/* ========================== */
volatile uint64_t total_connections = 0;
volatile uint64_t successful_handshakes = 0;
volatile uint64_t failed_handshakes = 0;
volatile uint64_t total_handshake_cycles = 0;
volatile uint64_t active_connections = 0;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* ========================== */
/* STRUCT FOR THREAD ARGS */
/* ========================== */
typedef struct {
    int client_fd;
    SSL_CTX *ctx;
} client_args_t;

/* ========================== */
/* OPENSSL INIT */
/* ========================== */
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Load providers so hybrid PQC signature algorithms are recognized */
    if (OSSL_PROVIDER_load(NULL, "default") == NULL) {
        fprintf(stderr, "Failed to load default provider\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (OSSL_PROVIDER_load(NULL, "oqsprovider") == NULL) {
        fprintf(stderr, "Failed to load OQS provider\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

SSL_CTX* create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* PQC group */
    if (SSL_CTX_set1_groups_list(ctx, HANDSHAKE_ALGO) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key mismatch\n");
        exit(1);
    }
}

/* ========================== */
/* METRICS LOGGER */
/* ========================== */
void* metrics_logger(void* arg) {
    (void)arg;

    /* Write CSV header */
    FILE *csv = fopen("metrics.csv", "w");
    if (csv) {
        fprintf(csv, "timestamp,total_connections,active_connections,"
                      "successful_handshakes,failed_handshakes,"
                      "avg_handshake_cycles\n");
        fclose(csv);
    }

    while (1) {
        sleep(1);

        pthread_mutex_lock(&lock);

        uint64_t avg_cycles = 0;
        if (successful_handshakes > 0)
            avg_cycles = total_handshake_cycles / successful_handshakes;

        // printf("\n====== SERVER METRICS ======\n");
        // printf("Total connections      : %lu\n", total_connections);
        // printf("Active connections     : %lu\n", active_connections);
        // printf("Successful handshakes  : %lu\n", successful_handshakes);
        // printf("Failed handshakes      : %lu\n", failed_handshakes);
        // printf("Avg handshake cycles   : %lu\n", avg_cycles);
        // printf("============================\n\n");

        /* Append to CSV */
        csv = fopen("metrics.csv", "a");
        if (csv) {
            fprintf(csv, "%ld,%lu,%lu,%lu,%lu,%lu\n",
                    (long)time(NULL),
                    total_connections, active_connections,
                    successful_handshakes, failed_handshakes,
                    avg_cycles);
            fclose(csv);
        }

        pthread_mutex_unlock(&lock);
    }
}

/* ========================== */
/* CLIENT HANDLER */
/* ========================== */
void* handle_client(void* arg) {
    client_args_t *args = (client_args_t*)arg;

    int client = args->client_fd;
    SSL_CTX *ctx = args->ctx;
    free(args);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        close(client);
        return NULL;
    }

    SSL_set_fd(ssl, client);

    pthread_mutex_lock(&lock);
    total_connections++;
    active_connections++;
    pthread_mutex_unlock(&lock);

    uint64_t start = rdtscp();

    if (SSL_accept(ssl) <= 0) {
        pthread_mutex_lock(&lock);
        failed_handshakes++;
        pthread_mutex_unlock(&lock);
        ERR_print_errors_fp(stderr);
    } else {
        uint64_t end = rdtscp();

        pthread_mutex_lock(&lock);
        successful_handshakes++;
        total_handshake_cycles += (end - start);
        pthread_mutex_unlock(&lock);

        /* optional read/write */
        // char buffer[1024];
        // int bytes = SSL_read(ssl, buffer, sizeof(buffer)-1);

        // if (bytes > 0) {
        //     buffer[bytes] = '\0';
        // }

        // SSL_write(ssl, "Hello from PQC TLS server\n", 26);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);

    pthread_mutex_lock(&lock);
    active_connections--;
    pthread_mutex_unlock(&lock);

    return NULL;
}

/* ========================== */
/* MAIN */
/* ========================== */
int main() {
    int sock;
    struct sockaddr_in addr;
    int opt = 1;

    init_openssl();
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1000) < 0) { // backlog of 1000 *****************************
        perror("listen");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("PQC TLS Server running on port %d...\n", PORT);

    pthread_t logger_thread;
    if (pthread_create(&logger_thread, NULL, metrics_logger, NULL) != 0) {
        perror("pthread_create");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int client;
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);

        client = accept(sock, (struct sockaddr*)&client_addr, &len);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }

            perror("accept");
            continue;
        }

        client_args_t *args = malloc(sizeof(client_args_t));
        if (!args) {
            perror("malloc");
            close(client);
            continue;
        }

        args->client_fd = client;
        args->ctx = ctx;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, args) != 0) {
            perror("pthread_create");
            close(client);
            free(args);
            continue;
        }

        pthread_detach(tid);
    }

    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
}
