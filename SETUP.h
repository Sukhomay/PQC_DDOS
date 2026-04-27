#ifndef SETUP_H
#define SETUP_H

#include <stdint.h>

#define PORT 4443
#define HANDSHAKE_ALGO "p384_mlkem768"
#define SIGNATURE_ALGO "p384_mldsa65"
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"


/* ========================== */
/* RDTSC TIMER */
/* ========================== */
static __inline__ uint64_t rdtscp() {
    unsigned int lo, hi;
    __asm__ __volatile__ (
        "rdtscp" : "=a"(lo), "=d"(hi) :: "%rcx"
    );
    return ((uint64_t)hi << 32) | lo;
}

#endif /* SETUP_H */
