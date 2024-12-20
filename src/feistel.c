#include "feistel.h"
#include <assert.h>
#include <math.h>
#include <openssl/sha.h>
#include <string.h>
#include "constants.h"
#define ROUNDS 7

#if (PQPAKE_SYM_KEY_SIZE==32)
#define SHA_OPT SHA256
#elif (PQPAKE_SYM_KEY_SIZE==64)
#define SHA_OPT SHA512
#endif
/**
 * @param hash_index Unique index of the hash function
 * @param sym_key Symmetric key of size PQPAKE_SYM_KEY_SIZE (64 bytes)
 * @param message_size Size of the message to hash
 * @param message Buffer to hash. Size is {message_size}
 * @param hashed_message Operation result. Size is FEISTEL_HALF_MESSAGE_SIZE
 * @note hashed_message must be allocated by the caller
 */
void hash(int hash_index,
          const uint8_t* sym_key,
          size_t message_size,
          const uint8_t* message,
          uint8_t* hashed_message) {
  const int hash_count = (int)ceil((float)message_size / PQPAKE_SYM_KEY_SIZE);
  const int input_string_size = 2 + PQPAKE_SYM_KEY_SIZE + message_size;

  uint8_t hashing_result[hash_count * PQPAKE_SYM_KEY_SIZE];
  memset(hashing_result, 0, hash_count * PQPAKE_SYM_KEY_SIZE);

  uint8_t input_string[input_string_size];
  memset(input_string, 0, input_string_size);

  input_string[1] = hash_index;
  memcpy(input_string + 2, sym_key, PQPAKE_SYM_KEY_SIZE);
  memcpy(input_string + 2 + PQPAKE_SYM_KEY_SIZE, message, message_size);

  for (int round = 0; round < hash_count; round++) {
    input_string[0] = round;

    SHA_OPT(input_string, input_string_size,
           hashing_result + round * PQPAKE_SYM_KEY_SIZE);
  }

  memcpy(hashed_message, hashing_result, message_size);
}

void pqpake_ic_feistel_encrypt(const uint8_t* sym_key,
                               size_t message_size,
                               const uint8_t* clear_message,
                               uint8_t* encrypted_message) {
  //assert(message_size % 2 == 0 && "message_size must be even");

  const size_t half_size = message_size / 2;

  uint8_t left[half_size];
  uint8_t right[half_size];

  memcpy(left, clear_message, half_size);
  memcpy(right, clear_message + half_size, half_size);

  for (int i = 0; i < ROUNDS; i++) {
    uint8_t hashed_right[half_size];
    hash(2 * i, sym_key, half_size, right, hashed_right);
    uint8_t new_left[half_size];
    for (int j = 0; j < half_size; j++) {
      new_left[j] = left[j] ^ hashed_right[j];
    }

    uint8_t hashed_new_left[half_size];
    hash(2 * i + 1, sym_key, half_size, new_left, hashed_new_left);
    uint8_t new_right[half_size];
    for (int j = 0; j < half_size; j++) {
      new_right[j] = right[j] ^ hashed_new_left[j];
    }

    memcpy(right, new_right, half_size);
    memcpy(left, new_left, half_size);
  }

  memcpy(encrypted_message, left, half_size);
  memcpy(encrypted_message + half_size, right, half_size);
}

void pqpake_ic_feistel_decrypt(const uint8_t* sym_key,
                               size_t message_size,
                               const uint8_t* encrypted_message,
                               uint8_t* clear_message) {
  assert(message_size % 2 == 0 && "message_size must be even");

  const size_t half_size = message_size / 2;

  uint8_t left[half_size];
  uint8_t right[half_size];

  memcpy(left, encrypted_message, half_size);
  memcpy(right, encrypted_message + half_size, half_size);

  for (int i = ROUNDS - 1; i >= 0; i--) {
    uint8_t hashed_left[half_size];
    hash(2 * i + 1, sym_key, half_size, left, hashed_left);
    uint8_t new_right[half_size];
    for (int j = 0; j < half_size; j++) {
      new_right[j] = right[j] ^ hashed_left[j];
    }

    uint8_t hashed_new_right[half_size];
    hash(2 * i, sym_key, half_size, new_right, hashed_new_right);
    uint8_t new_left[half_size];
    for (int j = 0; j < half_size; j++) {
      new_left[j] = left[j] ^ hashed_new_right[j];
    }

    memcpy(left, new_left, half_size);
    memcpy(right, new_right, half_size);
  }

  memcpy(clear_message, left, half_size);
  memcpy(clear_message + half_size, right, half_size);
}
