#include "api.h"
#include "constants.h"
#include <assert.h>
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#define BASE CRYPTO_BASE
#define COEFF_SIZE CRYPTO_N

#if (COEFF_SIZE == 512)
void pqpake_ic_encode(const uint8_t *input, uint8_t *output)
{
  uint16_t coefficients[COEFF_SIZE] = {0}; // 13 bits per coefficient
  mpz_t total, pow_base;
  mpz_init(total);
  mpz_init(pow_base);
  mpz_set_ui(pow_base, 1);

  for (int i = 0; i < COEFF_SIZE / 8; i++)
  {
    coefficients[8 * i + 0] = input[13 * i + 0] | (((uint16_t)input[13 * i + 1] & 0x1f) << 8);
    coefficients[8 * i + 1] = (input[13 * i + 1] >> 5) | (((uint16_t)input[13 * i + 2]) << 3) | (((uint16_t)input[13 * i + 3] & 0x03) << 11);
    coefficients[8 * i + 2] = (input[13 * i + 3] >> 2) | (((uint16_t)input[13 * i + 4] & 0x7f) << 6);
    coefficients[8 * i + 3] = (input[13 * i + 4] >> 7) | (((uint16_t)input[13 * i + 5]) << 1) | (((uint16_t)input[13 * i + 6] & 0x0f) << 9);
    coefficients[8 * i + 4] = (input[13 * i + 6] >> 4) | (((uint16_t)input[13 * i + 7]) << 4) | (((uint16_t)input[13 * i + 8] & 0x01) << 12);
    coefficients[8 * i + 5] = (input[13 * i + 8] >> 1) | (((uint16_t)input[13 * i + 9] & 0x3f) << 7);
    coefficients[8 * i + 6] = (input[13 * i + 9] >> 6) | (((uint16_t)input[13 * i + 10]) << 2) | (((uint16_t)input[13 * i + 11] & 0x07) << 10);
    coefficients[8 * i + 7] = (input[13 * i + 11] >> 3) | (((uint16_t)input[13 * i + 12]) << 5);
  }
  /* total = \sum_{i=0}^{1023} coeffs[i] * base^i */
  for (int i = 0; i < COEFF_SIZE; i++)
  {
    mpz_addmul_ui(total, pow_base, coefficients[i]);

    mpz_mul_ui(pow_base, pow_base, BASE);
  }

  /** @note the number is stored in reverse-order bytes */
  memset(output, 0, PQPAKE_ENCODEDPK_SIZE);
  mpz_export(output, NULL, -1, 1, 0, 0, total);

  unsigned char padByte[1];
  RAND_bytes(padByte, 1);
  output[PQPAKE_ENCODEDPK_SIZE - 1] |= *padByte & ((uint8_t)0xff << (8 - (PQPAKE_PADBITS)));

  if (PQPAKE_ENCODEDPK_SIZE % 2 != 0)
  {
    RAND_bytes(padByte, 1);
    output[PQPAKE_ENCODEDPK_SIZE] = *padByte;
  }
  mpz_clear(total);
  mpz_clear(pow_base);
}

void pqpake_ic_decode(uint8_t *input, uint8_t *output)
{
  input[PQPAKE_ENCODEDPK_SIZE - 1] &= (0xff >> (PQPAKE_PADBITS));

  uint16_t coefficients[COEFF_SIZE] = {0};
  mpz_t total;
  mpz_init(total);

  mpz_import(total, PQPAKE_ENCODEDPK_SIZE, -1, 1, 0, 0, input);

  for (int i = 0; i < COEFF_SIZE; i++)
  {
    coefficients[i] = mpz_fdiv_ui(total, BASE);
    mpz_fdiv_q_ui(total, total, BASE);
  }
  for (int i = 0; i < COEFF_SIZE / 8; i++)
  {
    output[13 * i + 0] = coefficients[8 * i + 0] & 0xff;
    output[13 * i + 1] = (coefficients[8 * i + 0] >> 8) | ((coefficients[8 * i + 1] & 0x07) << 5);
    output[13 * i + 2] = (coefficients[8 * i + 1] >> 3) & 0xff;
    output[13 * i + 3] = (coefficients[8 * i + 1] >> 11) | ((coefficients[8 * i + 2] & 0x3f) << 2);
    output[13 * i + 4] = (coefficients[8 * i + 2] >> 6) | ((coefficients[8 * i + 3] & 0x01) << 7);
    output[13 * i + 5] = (coefficients[8 * i + 3] >> 1) & 0xff;
    output[13 * i + 6] = (coefficients[8 * i + 3] >> 9) | ((coefficients[8 * i + 4] & 0x0f) << 4);
    output[13 * i + 7] = (coefficients[8 * i + 4] >> 4) & 0xff;
    output[13 * i + 8] = (coefficients[8 * i + 4] >> 12) | ((coefficients[8 * i + 5] & 0x7f) << 1);
    output[13 * i + 9] = (coefficients[8 * i + 5] >> 7) | ((coefficients[8 * i + 6] & 0x03) << 6);
    output[13 * i + 10] = (coefficients[8 * i + 6] >> 2) & 0xff;
    output[13 * i + 11] = (coefficients[8 * i + 6] >> 10) | ((coefficients[8 * i + 7] & 0x1f) << 3);
    output[13 * i + 12] = (coefficients[8 * i + 7] >> 5);
  }
}

#elif (COEFF_SIZE == 1024)

void pqpake_ic_encode(const uint8_t *input, uint8_t *output)
{
  uint16_t coefficients[COEFF_SIZE] = {0}; // 14 bits per coefficient
  mpz_t total, pow_base;
  mpz_init(total);
  mpz_init(pow_base);
  mpz_set_ui(pow_base, 1);

  for (int i = 0; i < COEFF_SIZE / 4; i++)
  {
    coefficients[4 * i + 0] = input[7 * i + 0] | (((uint16_t)input[7 * i + 1] & 0x3f) << 8);
    coefficients[4 * i + 1] = (input[7 * i + 1] >> 6) | (((uint16_t)input[7 * i + 2]) << 2) | (((uint16_t)input[7 * i + 3] & 0x0f) << 10);
    coefficients[4 * i + 2] = (input[7 * i + 3] >> 4) | (((uint16_t)input[7 * i + 4]) << 4) | (((uint16_t)input[7 * i + 5] & 0x03) << 12);
    coefficients[4 * i + 3] = (input[7 * i + 5] >> 2) | (((uint16_t)input[7 * i + 6]) << 6);
  }
  /* total = \sum_{i=0}^{1023} coeffs[i] * base^i */
  for (int i = 0; i < COEFF_SIZE; i++)
  {
    mpz_addmul_ui(total, pow_base, coefficients[i]);

    mpz_mul_ui(pow_base, pow_base, BASE);
  }

  /** @note the number is stored in reverse-order bytes */
  memset(output, 0, PQPAKE_ENCODEDPK_SIZE);
  mpz_export(output, NULL, -1, 1, 0, 0, total);

  unsigned char padByte[1];
  RAND_bytes(padByte, 1);

  //printf("%d\n",PQPAKE_PADBITS);
  output[PQPAKE_ENCODEDPK_SIZE - 1] |= *padByte & ((uint8_t)0xff << (8 - (PQPAKE_PADBITS)));

  if (PQPAKE_ENCODEDPK_SIZE % 2 != 0)
  {
    RAND_bytes(padByte, 1);
    output[PQPAKE_ENCODEDPK_SIZE] = *padByte;
  }
  mpz_clear(total);
  mpz_clear(pow_base);
}

void pqpake_ic_decode(uint8_t *input, uint8_t *output)
{
  input[PQPAKE_ENCODEDPK_SIZE - 1] &= (0xff >> (PQPAKE_PADBITS));
  uint16_t coefficients[COEFF_SIZE] = {0};
  mpz_t total;
  mpz_init(total);

  mpz_import(total, PQPAKE_ENCODEDPK_SIZE, -1, 1, 0, 0, input);

  for (int i = 0; i < COEFF_SIZE; i++)
  {
    coefficients[i] = mpz_fdiv_ui(total, BASE);
    mpz_fdiv_q_ui(total, total, BASE);
  }

  for (int i = 0; i < COEFF_SIZE / 4; i++)
  {
    output[7 * i + 0] = coefficients[4 * i + 0] & 0xff;
    output[7 * i + 1] = ((coefficients[4 * i + 0] >> 8) | (coefficients[4 * i + 1] << 6)) & 0xff;
    output[7 * i + 2] = ((coefficients[4 * i + 1] >> 2)) & 0xff;
    output[7 * i + 3] = ((coefficients[4 * i + 1] >> 10) | (coefficients[4 * i + 2] << 4)) & 0xff;
    output[7 * i + 4] = ((coefficients[4 * i + 2] >> 4)) & 0xff;
    output[7 * i + 5] = ((coefficients[4 * i + 2] >> 12) | (coefficients[4 * i + 3] << 2)) & 0xff;
    output[7 * i + 6] = ((coefficients[4 * i + 3] >> 6)) & 0xff;
  }
  mpz_clear(total);
}
#endif

int pqpake_ic_value_is_not_in_range(const uint8_t *value)
{
  mpz_t total, max_pow_base;
  mpz_init(total);
  mpz_init(max_pow_base);

  mpz_init_set_ui(max_pow_base, BASE);
  mpz_pow_ui(max_pow_base, max_pow_base, COEFF_SIZE);

  mpz_import(total, PQPAKE_ENCODEDPK_SIZE, -1, 1, 0, 0, value);

  int res = mpz_cmp(total, max_pow_base) >= 0;

  mpz_clear(total);
  mpz_clear(max_pow_base);

  return res;
}
