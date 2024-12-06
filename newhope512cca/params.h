#ifndef PARAMS_H
#define PARAMS_H

//#define MY_DEBUG

#ifndef NEWHOPE_N
#define NEWHOPE_N 512
#endif

//#define NEWHOPE_Q 12289 
//#define BITS_Q 14

#define NEWHOPE_Q 7681 
#define NEWHOPE_K 12           /* used in noise sampling */
#define BITS_Q 13

#define BIT_STRENGTH 128
#define ENCODE_BLK  BIT_STRENGTH

#define NEWHOPE_SYMBYTES (BIT_STRENGTH >> 3)   /* size of shared key, seeds/coins, and hashes */

#define NEWHOPE_POLYBYTES            ((BITS_Q*NEWHOPE_N)/8)
#define NEWHOPE_POLYCOMPRESSEDBYTES  (( 3*NEWHOPE_N)/8)

#define NEWHOPE_CPAPKE_PUBLICKEYBYTES  (NEWHOPE_POLYBYTES + NEWHOPE_SYMBYTES)
#define NEWHOPE_CPAPKE_SECRETKEYBYTES  (NEWHOPE_POLYBYTES)
#define NEWHOPE_CPAPKE_CIPHERTEXTBYTES (NEWHOPE_POLYBYTES + NEWHOPE_POLYCOMPRESSEDBYTES)

#define NEWHOPE_CPAKEM_PUBLICKEYBYTES NEWHOPE_CPAPKE_PUBLICKEYBYTES
#define NEWHOPE_CPAKEM_SECRETKEYBYTES NEWHOPE_CPAPKE_SECRETKEYBYTES
#define NEWHOPE_CPAKEM_CIPHERTEXTBYTES NEWHOPE_CPAPKE_CIPHERTEXTBYTES

#define NEWHOPE_CCAKEM_PUBLICKEYBYTES NEWHOPE_CPAPKE_PUBLICKEYBYTES
#define NEWHOPE_CCAKEM_SECRETKEYBYTES (NEWHOPE_CPAPKE_SECRETKEYBYTES + NEWHOPE_CPAPKE_PUBLICKEYBYTES + NEWHOPE_SYMBYTES)
#define NEWHOPE_CCAKEM_CIPHERTEXTBYTES (NEWHOPE_CPAPKE_CIPHERTEXTBYTES)  /* Second part is for Targhi-Unruh */
// #define NEWHOPE_CCAKEM_CIPHERTEXTBYTES (NEWHOPE_CPAPKE_CIPHERTEXTBYTES + NEWHOPE_SYMBYTES)  /* Second part is for Targhi-Unruh */

#endif