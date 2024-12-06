#include <string.h>
#include "api.h"
#include "cpapke.h"
#include "params.h"
#include "rng.h"
#include "fips202.h"
#include "verify.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA secure NewHope key encapsulation
*              mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
  size_t i;

  cpapke_keypair(pk, sk);                                                   /* First put the actual secret key into sk */
  sk += NEWHOPE_CPAPKE_SECRETKEYBYTES;

  for(i=0;i<NEWHOPE_CPAPKE_PUBLICKEYBYTES;i++)                              /* Append the public key for re-encryption */
    sk[i] = pk[i];
  sk += NEWHOPE_CPAPKE_PUBLICKEYBYTES;

  //shake256(sk, NEWHOPE_SYMBYTES, pk, NEWHOPE_CPAPKE_PUBLICKEYBYTES);        /* Append the hash of the public key */
  //sk += NEWHOPE_SYMBYTES;

  randombytes(sk, NEWHOPE_SYMBYTES);                                        /* Append the value s for pseudo-random output on reject */

  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) //, const unsigned char *sk
{
  unsigned char k_coins[2*NEWHOPE_SYMBYTES];
  unsigned char buf[3*NEWHOPE_SYMBYTES];

  randombytes(buf,NEWHOPE_SYMBYTES);                                             /*gen m*/
  memcpy(buf+NEWHOPE_SYMBYTES,pk,2*NEWHOPE_SYMBYTES);                            /*copy id(pk)*/

  shake256(k_coins,2*NEWHOPE_SYMBYTES,buf,3*NEWHOPE_SYMBYTES);                   /* k,coin<-shake(m,id(pk)) */
  
  cpapke_enc(ct, buf, pk, k_coins+NEWHOPE_SYMBYTES);                             /* ct<-enc(pk,m;r),coins are in buf+NEWHOPE_SYMBYTES */

  shake256(ss, NEWHOPE_SYMBYTES, buf, NEWHOPE_SYMBYTES);                         /* hash m to ss */
  return 0;
}


/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
  //add here
  int i, fail;
  unsigned char ct_cmp[NEWHOPE_CPAKEM_CIPHERTEXTBYTES];
  unsigned char buf[3*NEWHOPE_SYMBYTES];
  unsigned char k_coins[2*NEWHOPE_SYMBYTES];                                                /* Will contain key, coins, qrom-hash */
  const unsigned char *pk = sk+NEWHOPE_CPAPKE_SECRETKEYBYTES;
  //to here

  cpapke_dec(buf, ct, sk);                                                                  /*m<-dec(ct)*/
  memcpy(buf+NEWHOPE_SYMBYTES,pk,2*NEWHOPE_SYMBYTES);                                       /*copy id(pk)*/
  shake256(k_coins, 2*NEWHOPE_SYMBYTES, buf, 3*NEWHOPE_SYMBYTES);                           /*(k,coins)<-shake256(m,id(pk))*/
  
  cpapke_enc(ct_cmp, buf, pk, k_coins+NEWHOPE_SYMBYTES);                                    /* coins are in k_coins_d+NEWHOPE_SYMBYTES */


  fail = verify(ct, ct_cmp, NEWHOPE_CPAKEM_CIPHERTEXTBYTES);
  //printf("%d",fail);
  //to here

  shake256(ss, NEWHOPE_SYMBYTES, buf, NEWHOPE_SYMBYTES);                          /* hash pre-k to ss */
  
  shake256(buf, NEWHOPE_SYMBYTES, pk, 2*NEWHOPE_SYMBYTES);                              //copy id(pk)
  shake256(buf+NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, ct, NEWHOPE_CCAKEM_CIPHERTEXTBYTES); // overwrite coins in k_coins_d with h(c)  
  cmov(buf+2*NEWHOPE_SYMBYTES, sk+NEWHOPE_CCAKEM_SECRETKEYBYTES-NEWHOPE_SYMBYTES, NEWHOPE_SYMBYTES, fail); // Overwrite pre-k with z on re-encryption failure 
  

  return 0;
}
