#ifndef CRYPTO_TOOLS_H
#define CRYPTO_TOOLS_H

#include <stdint.h>
#include <string.h>
#include "api.h"

#define IV_LENGTH 12
#define AUTH_TAG_LENGTH 16
#define SALT_LENGTH 32
#define KEY_LENGTH CRYPTO_N/32
#define HMAC_LENGTH KEY_LENGTH*2


void ae_encrypt(const uint8_t *key,  uint8_t *plaintext, int in_nbytes, uint8_t *ciphertext, int *out_nbytes);

void ae_decrypt(const uint8_t *key,  uint8_t *ciphertext, int in_nbytes, uint8_t *plaintext, int *out_nbytes);

void transcript_hmac( uint8_t **input, size_t *in_nbytes, int round, const uint8_t *key, size_t key_length, uint8_t *hmac);

void generate_salt(char *salt, int salt_len);

void derive_key( const uint8_t *password, int pwsize,  char *salt, uint8_t *key);

#endif