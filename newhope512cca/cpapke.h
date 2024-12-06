#ifndef INDCPA_H
#define INDCPA_H

#include "params.h"

void cpapke_keypair(unsigned char *pk, 
                    unsigned char *sk);

#ifdef MY_DEBUG
void cpapke_enc(unsigned char *c,
    const unsigned char *m,
    const unsigned char *pk, const unsigned char *sk,
    const unsigned char *coin);
#else
void cpapke_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins);
#endif

void cpapke_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

#endif
