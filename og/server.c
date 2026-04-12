#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <fcntl.h>      // fcntl()
#include <errno.h>      // errno

#define PORT 4443


static __inline__ uint64_t rdtscp() {
    unsigned int lo, hi;
    __asm__ __volatile__ (
        "rdtscp" : "=a"(lo), "=d"(hi) :: "%rcx"
    );
    return ((uint64_t)hi << 32) | lo;
}

int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl(F_GETFL)");
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("fcntl(F_SETFL)");
        return -1;
    }

    return 0;
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    /* Load PQC certificate */
    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);

    /* Load PQC private key */
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);

    /* Configure PQC KEM (Kyber) */
    SSL_CTX_set1_groups_list(ctx, "mlkem768");

    /*Verify certificate and private key loaded correctly */
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match certificate\n");
        exit(1);
    }
}

int main()
{
    int sock;
    struct sockaddr_in addr;

    SSL_CTX *ctx;
    SSL *ssl;

    init_openssl();

    ctx = create_context();
    configure_context(ctx);

    /* TCP Socket Setup */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 5);

    printf("PQC TLS Server listening...\n");

    while(1)
    {
        int client;
        struct sockaddr_in addr;
        int len = sizeof(addr);

        client = accept(sock, (struct sockaddr*)&addr, &len);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        /* ========================== */
        /* TLS HANDSHAKE STAGE */
        /* ========================== */

        printf("Starting TLS handshake...\n");

        uint64_t start = rdtscp();

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            uint64_t end = rdtscp();

            printf("Handshake complete\n");
            printf("==>> Server handshake cycles: %lu\n", (end - start));

            int group = SSL_get_negotiated_group(ssl);

            printf("Negotiated group NID: %d\n", group);
            printf("Group name: %s\n", SSL_group_to_name(ssl, group));

            if (group > 0) {
                const char *name = OBJ_nid2sn(group);

                if (name != NULL)
                    printf("Group: %s\n", name);
                else
                    printf("Group NID: %d \n", group);
            } else {
                printf("No group negotiated\n");
            }

            /* ========================== */
            /* CERTIFICATE VERIFICATION */
            /* ========================== */

            printf("Cipher: %s\n", SSL_get_cipher(ssl));

            /* ========================== */
            /* SECURE COMMUNICATION */
            /* ========================== */

            char buffer[1024];

            int bytes = SSL_read(ssl, buffer, sizeof(buffer));

            buffer[bytes] = '\0';

            printf("Client message: %s\n", buffer);

            SSL_write(ssl, "Hello from PQC TLS server\n", 26);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}