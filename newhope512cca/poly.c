#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "fips202.h"
#include "stdio.h"

/*************************************************
* Name:        coeff_freeze
* 
* Description: Fully reduces an integer modulo q in constant time
*
* Arguments:   uint16_t x: input integer to be reduced
*              
* Returns integer in {0,...,q-1} congruent to x modulo q
**************************************************/
static uint16_t coeff_freeze(uint16_t x)
{
  uint16_t m,r;
  int16_t c;
  r = x % NEWHOPE_Q;

  m = r - NEWHOPE_Q;
  c = m;
  c >>= 15;
  r = m ^ ((r^m)&c);

  return r;
}

/*************************************************
* Name:        flipabs
* 
* Description: Computes |(x mod q) - Q/2|
*
* Arguments:   uint16_t x: input coefficient
*              
* Returns |(x mod q) - Q/2|
**************************************************/
static uint16_t flipabs(uint16_t x)
{
  int16_t r,m;
  r = coeff_freeze(x);

  r = r - NEWHOPE_Q/2;
  m = r >> 15;
  return (r + m) ^ m;
}

#if 1
// (BITS_Q == 13)
void poly_frombytes(poly *r, const unsigned char *a)
{
    int i;
    for (i = 0; i < NEWHOPE_N / 8; i++)
    {
        r->coeffs[8 * i + 0] = a[13 * i + 0] | (((uint16_t)a[13 * i + 1] & 0x1f) << 8);
        r->coeffs[8 * i + 1] = (a[13 * i + 1] >> 5) | (((uint16_t)a[13 * i + 2]) << 3) | (((uint16_t)a[13 * i + 3] & 0x03) << 11);
        r->coeffs[8 * i + 2] = (a[13 * i + 3] >> 2) | (((uint16_t)a[13 * i + 4] & 0x7f) << 6);
        r->coeffs[8 * i + 3] = (a[13 * i + 4] >> 7) | (((uint16_t)a[13 * i + 5]) << 1) | (((uint16_t)a[13 * i + 6] & 0x0f) << 9);
        r->coeffs[8 * i + 4] = (a[13 * i + 6] >> 4) | (((uint16_t)a[13 * i + 7]) << 4) | (((uint16_t)a[13 * i + 8] & 0x01) << 12);
        r->coeffs[8 * i + 5] = (a[13 * i + 8] >> 1) | (((uint16_t)a[13 * i + 9] & 0x3f) << 7);
        r->coeffs[8 * i + 6] = (a[13 * i + 9] >> 6) | (((uint16_t)a[13 * i + 10]) << 2) | (((uint16_t)a[13 * i + 11] & 0x07) << 10);
        r->coeffs[8 * i + 7] = (a[13 * i + 11] >> 3) | (((uint16_t)a[13 * i + 12]) << 5);
    }
}
void poly_tobytes(unsigned char *r, const poly *p)
{ // 8 coeff --> BITS_Q byte
    int i, j;
    uint16_t t[8];
    for (i = 0; i < NEWHOPE_N / 8; i++)
    {
        for (j = 0; j < 8; j++) {
            t[j] = coeff_freeze(p->coeffs[8 * i + j]);
        }

        r[13 * i + 0] = t[0] & 0xff;
        r[13 * i + 1] = (t[0] >> 8) | ((t[1] & 0x07) << 5);
        r[13 * i + 2] = (t[1] >> 3) & 0xff;
        r[13 * i + 3] = (t[1] >> 11) | ((t[2] & 0x3f) << 2);
        r[13 * i + 4] = (t[2] >> 6) | ((t[3] & 0x01) << 7);
        r[13 * i + 5] = (t[3] >> 1) & 0xff;
        r[13 * i + 6] = (t[3] >> 9) | ((t[4] & 0x0f) << 4);
        r[13 * i + 7] = (t[4] >> 4) & 0xff;
        r[13 * i + 8] = (t[4] >> 12) | ((t[5] & 0x7f) << 1);
        r[13 * i + 9] = (t[5] >> 7) | ((t[6] & 0x03) << 6);
        r[13 * i + 10] = (t[6] >> 2) & 0xff;
        r[13 * i + 11] = (t[6] >> 10) | ((t[7] & 0x1f) << 3);
        r[13 * i + 12] = (t[7] >> 5);
    }
}

#else
/*************************************************
* Name:        poly_frombytes
* 
* Description: De-serialization of a polynomial
*
* Arguments:   - poly *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void poly_frombytes(poly *r, const unsigned char *a)
{
  int i;
  for(i=0;i<NEWHOPE_N/4;i++)
  {
    r->coeffs[4*i+0] =                               a[7*i+0]        | (((uint16_t)a[7*i+1] & 0x3f) << 8);
    r->coeffs[4*i+1] = (a[7*i+1] >> 6) | (((uint16_t)a[7*i+2]) << 2) | (((uint16_t)a[7*i+3] & 0x0f) << 10);
    r->coeffs[4*i+2] = (a[7*i+3] >> 4) | (((uint16_t)a[7*i+4]) << 4) | (((uint16_t)a[7*i+5] & 0x03) << 12);
    r->coeffs[4*i+3] = (a[7*i+5] >> 2) | (((uint16_t)a[7*i+6]) << 6);
  }
}

/*************************************************
* Name:        poly_tobytes
* 
* Description: Serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly *p:    pointer to input polynomial
**************************************************/
void poly_tobytes(unsigned char *r, const poly *p)
{
  int i;
  uint16_t t0,t1,t2,t3;
  for(i=0;i<NEWHOPE_N/4;i++)
  {
    t0 = coeff_freeze(p->coeffs[4*i+0]);
    t1 = coeff_freeze(p->coeffs[4*i+1]);
    t2 = coeff_freeze(p->coeffs[4*i+2]);
    t3 = coeff_freeze(p->coeffs[4*i+3]);

    r[7*i+0] =  t0 & 0xff;
    r[7*i+1] = (t0 >> 8) | (t1 << 6);
    r[7*i+2] = (t1 >> 2);
    r[7*i+3] = (t1 >> 10) | (t2 << 4);
    r[7*i+4] = (t2 >> 4);
    r[7*i+5] = (t2 >> 12) | (t3 << 2);
    r[7*i+6] = (t3 >> 6);
  }
}
#endif

/*************************************************
* Name:        poly_compress
* 
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly *p:    pointer to input polynomial
**************************************************/
void poly_compress(unsigned char *r, const poly *p)
{
  unsigned int i,j,k=0;

  uint32_t t[8];

  for(i=0;i<NEWHOPE_N;i+=8)
  {
    for(j=0;j<8;j++)
    {
      t[j] = coeff_freeze(p->coeffs[i+j]);
      t[j] = (((t[j] << 3) + NEWHOPE_Q/2)/NEWHOPE_Q) & 0x7;
    }

    r[k]   =  t[0]       | (t[1] << 3) | (t[2] << 6);
    r[k+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[k+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    k += 3;
  }
}

/*************************************************
* Name:        poly_decompress
* 
* Description: De-serialization and subsequent decompression of a polynomial; 
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void poly_decompress(poly *r, const unsigned char *a)
{
  unsigned int i,j;
  for(i=0;i<NEWHOPE_N;i+=8)
  {
    r->coeffs[i+0] =  a[0] & 7;
    r->coeffs[i+1] = (a[0] >> 3) & 7;
    r->coeffs[i+2] = (a[0] >> 6) | ((a[1] << 2) & 4);
    r->coeffs[i+3] = (a[1] >> 1) & 7;
    r->coeffs[i+4] = (a[1] >> 4) & 7;
    r->coeffs[i+5] = (a[1] >> 7) | ((a[2] << 1) & 6);
    r->coeffs[i+6] = (a[2] >> 2) & 7;
    r->coeffs[i+7] = (a[2] >> 5);
    a += 3;
    for(j=0;j<8;j++)
      r->coeffs[i+j] = ((uint32_t)r->coeffs[i+j] * NEWHOPE_Q + 4) >> 3;
  }
}

/*************************************************
* Name:        poly_frommsg
* 
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:                  pointer to output polynomial
*              - const unsigned char *msg: pointer to input message
**************************************************/
void poly_frommsg(poly *r, const unsigned char *msg)
{
  unsigned int i,j,mask;
  for(i=0;i< NEWHOPE_SYMBYTES;i++) // XXX: MACRO for 32
  {
    for(j=0;j<8;j++)
    {
      mask = -((msg[i] >> j)&1);
      r->coeffs[8*i+j+  0] = mask & (NEWHOPE_Q/2);
      r->coeffs[8*i+j+ ENCODE_BLK] = mask & (NEWHOPE_Q/2);
//#if (NEWHOPE_N == 1024)
      r->coeffs[8*i+j+ 2*ENCODE_BLK] = mask & (NEWHOPE_Q/2);
      r->coeffs[8*i+j+ 3*ENCODE_BLK] = mask & (NEWHOPE_Q/2);
//#endif
    }
  }
}

/*************************************************
* Name:        poly_tomsg
* 
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - unsigned char *msg: pointer to output message
*              - const poly *x:      pointer to input polynomial
**************************************************/
void poly_tomsg(unsigned char *msg, const poly *x)
{
  unsigned int i;
  uint16_t t;

  for(i=0;i< NEWHOPE_SYMBYTES;i++)
    msg[i] = 0;

  for(i=0;i< BIT_STRENGTH;i++)
  {
    t  = flipabs(x->coeffs[i+  0]);
    t += flipabs(x->coeffs[i+ ENCODE_BLK]);
//#if (NEWHOPE_N == 1024)
    t += flipabs(x->coeffs[i+ 2 * ENCODE_BLK]);
    t += flipabs(x->coeffs[i+ 3 * ENCODE_BLK]);
    t = ((t - NEWHOPE_Q));
//#else
//    t = ((t - NEWHOPE_Q/2));
//#endif

    t >>= 15;
    msg[i>>3] |= t<<(i&7);
  }
}
 
/*************************************************
* Name:        poly_uniform
* 
* Description: Sample a polynomial deterministically from a seed,
*              with output polynomial looking uniformly random
*
* Arguments:   - poly *a:                   pointer to output polynomial
*              - const unsigned char *seed: pointer to input seed
**************************************************/
void poly_uniform(poly *a, const unsigned char *seed)
{
  unsigned int ctr=0;
  uint16_t val[8];
  uint64_t state[25];
  uint8_t buf[SHAKE128_RATE];
  uint8_t extseed[NEWHOPE_SYMBYTES+1];
  int i,j,k,total=0;

  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    extseed[i] = seed[i];

  for(i=0;i<NEWHOPE_N/64;i++) /* generate a in blocks of 64 coefficients */
  {
    ctr = 0;
    extseed[NEWHOPE_SYMBYTES] = i; /* domain-separate the 16 independent calls */
    shake128_absorb(state, extseed, NEWHOPE_SYMBYTES+1);
    
    while(ctr < 64) /* Very unlikely to run more than once */
    {
      shake128_squeezeblocks(buf,1,state);
      for(j=0;j+13<SHAKE128_RATE && ctr < 64;j+=13)
      {
        val[0] = (buf[j] | ((uint16_t) buf[j+1] << 8)) & 0x1FFF;                                               /* buf[j+1][5]|buf[j][8]   */
        val[1] = ((buf[j+1]>>5)    | ((uint16_t) buf[j+2] << 3) |  ((uint16_t) buf[j+3] << 11))  & 0x1FFF;     /* buf[j+3][2] |buf[j+2][8]|buf[j+1][3]  */
        val[2] = ((buf[j+3] >> 2)  | ((uint16_t) buf[j+4] << 6)) & 0x1FFF;                                     /* buf[j+4][7]|buf[j+3][6]       */
        val[3] = ((buf[j+4] >> 7)  | ((uint16_t) buf[j+5] << 1) | ((uint16_t) buf[j+6] << 9)) & 0x1FFF;        /* buf[j+6][4]|buf[j+5][8] | buf[j+4][1]      */
        val[4] = ((buf[j+6] >> 4)  | ((uint16_t) buf[j+7] << 4) | ((uint16_t) buf[j+8] << 12)) & 0x1FFF;       /* buf[j+8][1]|buf[j+7][8] | buf[j+6][4]      */
        val[5] = ((buf[j+8] >> 1)  | ((uint16_t) buf[j+9] << 7))  & 0x1FFF;                                    /* buf[j+9][6]|buf[j+8][7]  */
        val[6] = ((buf[j+9] >> 6)  | ((uint16_t) buf[j+10] << 2) |  ((uint16_t) buf[j+11] << 10)) & 0x1FFF;    /* buf[j+11][3]|buf[j+10][8]|buf[j+9][2]  */
        val[7] = ((buf[j+11] >> 3) | ((uint16_t) buf[j+12] << 5)) & 0x1FFF ;                                   /* buf[j+12][8]|buf[j+11][5]  */

        for(k=0;k<8;k++){
          if(val[k] < NEWHOPE_Q&& ctr < 64){a->coeffs[i*64+ctr] = val[k];
          ctr++;}
        }
      }
    }
  }

}



/*************************************************
* Name:        hw
* 
* Description: Compute the Hamming weight of a byte
*
* Arguments:   - unsigned char a: input byte
**************************************************/
static unsigned char hw(unsigned char a)
{
  unsigned char i, r = 0;
  for(i=0;i<8;i++)
    r += (a >> i) & 1;
  return r;
}

static unsigned char hw_half(unsigned char a)
{
  unsigned char i, r = 0;
  for(i=0;i<4;i++)
    r += (a >> i) & 1;
  return r;
}



/*************************************************
* Name:        poly_sample
* 
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter k=12
*
* Arguments:   - poly *r:                   pointer to output polynomial
*              - const unsigned char *seed: pointer to input seed 
*              - unsigned char nonce:       one-byte input nonce
**************************************************/
void poly_sample(poly *r, const unsigned char *seed, unsigned char nonce)
{
  unsigned char buf[192], a, b, c;
//  uint32_t t, d, a, b, c;
  int i,j;

  unsigned char extseed[NEWHOPE_SYMBYTES+2];

  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    extseed[i] = seed[i];
  extseed[NEWHOPE_SYMBYTES] = nonce;

  for(i=0;i<NEWHOPE_N/64;i++) /* Generate noise in blocks of 64 coefficients */
  {
    extseed[NEWHOPE_SYMBYTES+1] = i;
    shake256(buf,192,extseed,NEWHOPE_SYMBYTES+2);//改成squeeze
    for(j=0;j<64;j++)
    {
      a = buf[3*j];
      b = buf[3*j+1];
      c = buf[3*j+2];
      r->coeffs[64*i+j] = hw(a) +hw_half(c) + NEWHOPE_Q - hw(b)-hw_half(c>>4) ;
      
    }
  }
}

/*************************************************
* Name:        poly_pointwise
* 
* Description: Multiply two polynomials pointwise (i.e., coefficient-wise).
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
// Here needs modification
//void poly_mul_pointwise(poly *r, const poly *a, const poly *b)
//{
//  int i;
//  uint16_t t;
//  for(i=0;i<NEWHOPE_N;i++)
//  {
//    t            = montgomery_reduce(3186*b->coeffs[i]); /* t is now in Montgomery domain */
//    r->coeffs[i] = montgomery_reduce(a->coeffs[i] * t);  /* r->coeffs[i] is back in normal domain */
//  }
//}
void poly_mul_pointwise(poly *r, const poly *a, const poly *b)
{
    unsigned int i;
    for (i = 0; i < NEWHOPE_N / 4; i++) {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[ZETA_LHALF + i]);
        basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2],
            NEWHOPE_Q-zetas[ZETA_LHALF + i]);
    }
    poly_reduce(r);
}

/*************************************************
* Name:        poly_add
* 
* Description: Add two polynomials
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_add(poly *r, const poly *a, const poly *b)
{
  int i;
  for(i=0;i<NEWHOPE_N;i++)
    r->coeffs[i] = (a->coeffs[i] + b->coeffs[i]) % NEWHOPE_Q;
}

/*************************************************
* Name:        poly_sub
* 
* Description: Subtract two polynomials
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_sub(poly *r, const poly *a, const poly *b)
{
  int i;
  for(i=0;i<NEWHOPE_N;i++)
    r->coeffs[i] = (a->coeffs[i] + 3*NEWHOPE_Q - b->coeffs[i]) % NEWHOPE_Q;
}

void poly_reduce(poly *r)
{
    unsigned int i;
    for (i = 0; i < NEWHOPE_N; i++)
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

/*************************************************
* Name:        poly_ntt
* 
* Description: Forward NTT transform of a polynomial in place
*              Input is assumed to have coefficients in bitreversed order
*              Output has coefficients in normal order
*
* Arguments:   - poly *r: pointer to in/output polynomial
**************************************************/
void poly_ntt(poly *r)
{
    ntt(r->coeffs);
    poly_reduce(r);
  //mul_coefficients(r->coeffs, gammas_bitrev_montgomery);
  //ntt((uint16_t *)r->coeffs, gammas_bitrev_montgomery);
}

/*************************************************
* Name:        poly_invntt
* 
* Description: Inverse NTT transform of a polynomial in place
*              Input is assumed to have coefficients in normal order
*              Output has coefficients in normal order
*
* Arguments:   - poly *r: pointer to in/output polynomial
**************************************************/
// Here needs modification
void poly_invntt(poly *r)
{
    invntt(r->coeffs);
  //bitrev_vector(r->coeffs);
  //ntt((uint16_t *)r->coeffs, omegas_inv_bitrev_montgomery);
  //mul_coefficients(r->coeffs, gammas_inv_montgomery);
}

/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_tomont(poly *r)
{
    unsigned int i;
    const uint16_t f = (1ULL << 2 * MONT_POW) % NEWHOPE_Q; // 4613
    for (i = 0; i < NEWHOPE_N; i++)
        r->coeffs[i] = montgomery_reduce((uint32_t)r->coeffs[i] * f);
}