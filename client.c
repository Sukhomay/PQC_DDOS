#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdint.h>

#define PORT 4443

static __inline__ uint64_t rdtscp() {
    unsigned int lo, hi;
    __asm__ __volatile__ (
        "rdtscp" : "=a"(lo), "=d"(hi) :: "%rcx"
    );
    return ((uint64_t)hi << 32) | lo;
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    return ctx;
}

int main()
{
    int sock;
    struct sockaddr_in addr;

    SSL_CTX *ctx;
    SSL *ssl;

    init_openssl();

    ctx = create_context();

    /* Configure PQC KEM */
    SSL_CTX_set1_groups_list(ctx, "mlkem768");

    /* Set verification callback */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Load CA certificate (Trust self-signed certificate) */
    SSL_CTX_load_verify_locations(ctx, "server.crt", NULL);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    /* ========================== */
    /* TLS HANDSHAKE */
    /* ========================== */

    printf("Starting TLS handshake\n");

    uint64_t start = rdtscp();

    SSL_connect(ssl);

    uint64_t end = rdtscp();
    
    printf("==>> Client handshake cycles: %lu\n", (end - start));

    /* Get verification result for certificate */
    long verify_result = SSL_get_verify_result(ssl);

    /* Check verification result */
    if (verify_result == X509_V_OK) {
        printf("Certificate verification successful\n");
    } else {
        printf("Certificate verification failed: %ld\n", verify_result);
    }

    X509 *cert = SSL_get_peer_certificate(ssl);

    if (cert) {
        if (X509_check_host(cert, "localhost", 0, 0, NULL) == 1) {
            printf("Hostname verified\n");
        } else {
            printf("Hostname verification failed\n");
        }
        X509_free(cert);
    }

    printf("---- Handshake finished ----\n");

    /* ========================== */
    /* ENCRYPTED COMMUNICATION */
    /* ========================== */

    SSL_write(ssl, "Hello server", 12);

    char buffer[1024];

    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1); 

    if (bytes > 0) {
        // 2. Manually add the null-terminator at the end of the data
        buffer[bytes] = '\0';
        printf("Server reply: %s", buffer);
    } else {
        // Handle potential read error
        ERR_print_errors_fp(stderr);
    }


    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
}