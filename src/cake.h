#ifndef PQPAKE_CAKE_H
#define PQPAKE_CAKE_H
#include <stdint.h>
#include <string.h>
#include "constants.h"

typedef struct cake_agent {
  uint32_t session_id;
  uint8_t sym_key[PQPAKE_SYM_KEY_SIZE];

  size_t alice_size;
  uint8_t* alice_name;
  size_t bob_size;
  uint8_t* bob_name;

  uint8_t pk[PQPAKE_PK_SIZE];
  uint8_t epk[PQPAKE_EPK_SIZE];  // only used by alice
  uint8_t sk[PQPAKE_SK_SIZE];    // only used by alice
  uint8_t ss[32];
} cake_agent;

/**
 * Create and initialize agent internal state for Alice (request initiator)
 * @param session_id the common session id
 * @param password the common password (low entropy allowed)
 * @param password_size the size of the password
 * @param alice_name the name of the "Alice" device
 * @param alice_size the size of the name of the "Alice" device
 * @return a pointer to the agent internal state
 * @note the agent internal state must be freed with cake_free_agent
 */
cake_agent* cake_create_alice(uint32_t session_id,
                              const uint8_t* password,
                              size_t password_size,
                              const uint8_t* alice_name,
                              size_t alice_size);
/**
 * Create and initialize agent internal state for Bob (request responder)
 * @param session_id the common session id
 * @param password the common password (low entropy allowed)
 * @param password_size the size of the password
 * @param bob_name the name of the "Bob" device
 * @param bob_size the size of the name of the "Bob" device
 * @return a pointer to the agent internal state
 * @note the agent internal state must be freed with cake_free_agent
 */
cake_agent* cake_create_bob(uint32_t session_id,
                            const uint8_t* password,
                            size_t password_size,
                            const uint8_t* bob_name,
                            size_t bob_size);
/**
 * Free agent internal state
 * @param agent the agent internal state to free
 */
void cake_free_agent(cake_agent* agent);

void cake_create_message_step1(cake_agent* alice,
                                uint8_t** out,
                                size_t* out_size);
void cake_create_message_step2(cake_agent* bob,
                                const uint8_t* in,
                                uint8_t** out,
                                size_t* out_size);
void cake_create_message_step3(cake_agent* alice, const uint8_t* in);
const uint8_t* cake_get_shared_secret(const cake_agent* agent);

#endif  // PQPAKE_CAKE_H
