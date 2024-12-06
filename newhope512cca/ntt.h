#ifndef NTT_H
#define NTT_H

#include "inttypes.h"
#include "params.h"

// for q = 7681
#define ZETA_LEN 256

#define ZETA_LHALF (ZETA_LEN/2)

extern const uint16_t zetas[ZETA_LEN];
extern const uint16_t zetas_inv[ZETA_LEN];

extern uint16_t omegas_inv_bitrev_montgomery[];
extern uint16_t gammas_bitrev_montgomery[];
extern uint16_t gammas_inv_montgomery[];

void bitrev_vector(uint16_t* poly);
void mul_coefficients(uint16_t* poly, const uint16_t* factors);
//void ntt(uint16_t* poly, const uint16_t* omegas);
void ntt(uint16_t r[NEWHOPE_N]);
void invntt(uint16_t r[NEWHOPE_N]);
void basemul(uint16_t r[2],
    const uint16_t a[2],
    const uint16_t b[2],
    uint16_t zeta);

#endif
