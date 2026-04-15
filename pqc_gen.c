#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "SETUP.h"

#define CERT_VALIDITY_DAYS 365

static void print_openssl_errors(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}

static int add_extension(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ext = NULL;
    X509V3_CTX ctx;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (ext == NULL) {
        return 0;
    }

    if (X509_add_ext(cert, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        return 0;
    }

    X509_EXTENSION_free(ext);
    return 1;
}

static EVP_PKEY *generate_private_key(const char *algorithm)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (ctx == NULL) {
        print_openssl_errors("Failed to create a key generation context for the requested algorithm.");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        print_openssl_errors("Failed to initialize key generation.");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        print_openssl_errors("Failed to generate private key. Make sure the algorithm is a signature-capable key type such as mldsa44.");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    return pkey;
}

static X509 *generate_self_signed_cert(EVP_PKEY *pkey)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    unsigned long serial = (unsigned long)time(NULL);

    cert = X509_new();
    if (cert == NULL) {
        print_openssl_errors("Failed to allocate X509 certificate.");
        return NULL;
    }

    if (X509_set_version(cert, 2) != 1) {
        print_openssl_errors("Failed to set certificate version.");
        X509_free(cert);
        return NULL;
    }

    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)serial) != 1) {
        print_openssl_errors("Failed to set certificate serial number.");
        X509_free(cert);
        return NULL;
    }

    if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL ||
        X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * CERT_VALIDITY_DAYS) == NULL) {
        print_openssl_errors("Failed to set certificate validity window.");
        X509_free(cert);
        return NULL;
    }

    if (X509_set_pubkey(cert, pkey) != 1) {
        print_openssl_errors("Failed to attach public key to certificate.");
        X509_free(cert);
        return NULL;
    }

    name = (X509_NAME *)X509_get_subject_name(cert);
    if (name == NULL) {
        print_openssl_errors("Failed to get certificate subject.");
        X509_free(cert);
        return NULL;
    }

    if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                   (const unsigned char *)"IN", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
                                   (const unsigned char *)"WestBengal", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                                   (const unsigned char *)"Kharagpur", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                   (const unsigned char *)"IIT", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                                   (const unsigned char *)"CryptoLab", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *)"localhost", -1, -1, 0) != 1) {
        print_openssl_errors("Failed to build certificate subject name.");
        X509_free(cert);
        return NULL;
    }

    if (X509_set_issuer_name(cert, name) != 1) {
        print_openssl_errors("Failed to set certificate issuer.");
        X509_free(cert);
        return NULL;
    }

    if (!add_extension(cert, NID_basic_constraints, "critical,CA:FALSE") ||
        !add_extension(cert, NID_key_usage, "critical,digitalSignature,keyEncipherment") ||
        !add_extension(cert, NID_ext_key_usage, "serverAuth") ||
        !add_extension(cert, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1,IP:10.145.231.154")) {
        print_openssl_errors("Failed to add X509 extensions.");
        X509_free(cert);
        return NULL;
    }

    if (X509_sign(cert, pkey, NULL) <= 0) {
        print_openssl_errors("Failed to self-sign certificate. The selected algorithm may not support certificate signing.");
        X509_free(cert);
        return NULL;
    }

    return cert;
}

static int write_private_key(const char *path, EVP_PKEY *pkey)
{
    FILE *fp = fopen(path, "wb");
    int ok = 0;

    if (fp == NULL) {
        perror("Failed to open private key file");
        return 0;
    }

    ok = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    if (ok != 1) {
        print_openssl_errors("Failed to write private key.");
        return 0;
    }

    return 1;
}

static int write_certificate(const char *path, X509 *cert)
{
    FILE *fp = fopen(path, "wb");
    int ok = 0;

    if (fp == NULL) {
        perror("Failed to open certificate file");
        return 0;
    }

    ok = PEM_write_X509(fp, cert);
    fclose(fp);

    if (ok != 1) {
        print_openssl_errors("Failed to write certificate.");
        return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{
    const char *algorithm = SIGNATURE_ALGO;
    const char *cert_path = CERT_FILE;
    const char *key_path = KEY_FILE;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *oqs_provider = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    int exit_code = EXIT_FAILURE;

    if (argc > 4) {
        fprintf(stderr, "Usage: %s [signature_algo] [cert_file] [key_file]\n", argv[0]);
        fprintf(stderr, "Example: %s mldsa44 server.crt server.key\n", argv[0]);
        return EXIT_FAILURE;
    }
    algorithm = SIGNATURE_ALGO;

    if (argc >= 2) {
        cert_path = argv[1];
    }
    if (argc == 3) {
        key_path = argv[2];
    }

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    default_provider = OSSL_PROVIDER_load(NULL, "default");
    oqs_provider = OSSL_PROVIDER_load(NULL, "oqsprovider");

    if (default_provider == NULL || oqs_provider == NULL) {
        print_openssl_errors("Failed to load OpenSSL providers.");
        goto cleanup;
    }

    pkey = generate_private_key(algorithm);
    if (pkey == NULL) {
        goto cleanup;
    }

    cert = generate_self_signed_cert(pkey);
    if (cert == NULL) {
        goto cleanup;
    }

    if (!write_private_key(key_path, pkey) || !write_certificate(cert_path, cert)) {
        goto cleanup;
    }

    printf("Generated certificate and key successfully.\n");
    printf("Signature algorithm request : %s\n", algorithm);
    printf("Certificate file            : %s\n", cert_path);
    printf("Private key file            : %s\n", key_path);

    exit_code = EXIT_SUCCESS;

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(oqs_provider);
    OSSL_PROVIDER_unload(default_provider);
    EVP_cleanup();
    ERR_free_strings();

    return exit_code;
}
