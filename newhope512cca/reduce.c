#include "reduce.h"
#include "params.h"

//static const uint32_t qinv = 12287; // -inverse_mod(p,2^18)
static const uint32_t qinv = 7679; // -inverse_mod(p,2^18)
static const uint32_t rlog = MONT_POW;

//#define QINV 57857 // q^-1 mod 2^16
//#define MONT 4088 // 2^16 mod q

//#define QINV 254465 // q^-1 mod 2^18
//#define MONT 990 // 2^18 mod q

/*************************************************
* Name:        verify
* 
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, 
*              where R=2^18 (see value of rlog)
*
* Arguments:   - uint32_t a: input unsigned integer to be reduced; has to be in {0,...,1073491968}
*              
* Returns:     unsigned integer in {0,...,2^14-1} congruent to a * R^-1 modulo q.
**************************************************/
uint16_t montgomery_reduce(uint32_t a)
{
  uint32_t u;

  u = (a * qinv);
  u &= ((1<< rlog)-1);
  u *= NEWHOPE_Q;
  a = a + u;
  return a >> rlog;
}

/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              16-bit integer congruent to a mod q in {0,...,q}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {0,...,q} congruent to a modulo q.
**************************************************/
uint16_t barrett_reduce(uint32_t a) {
    uint32_t t;
    const uint16_t v = ((1U << BARRETT_BITS) + (NEWHOPE_Q-1)) / NEWHOPE_Q;

    t = (uint32_t)v*a >> BARRETT_BITS;
    t *= NEWHOPE_Q;
    return a - t;
}