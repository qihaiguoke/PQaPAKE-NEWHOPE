#include "cake.h"
#include <openssl/sha.h>
#include <stdio.h>
#include "ciphertext.h"
#include "commons.h"
#include "pake.h"
#include "publickey.h"
#include "api.h"
#define CAKE_step1_MESSAGE_SIZE PQPAKE_EPK_SIZE
#define CAKE_step2_MESSAGE_SIZE PQPAKE_ECT_SIZE

#if (CRYPTO_N==512)
#define PQPAKE_PROTO_CAKE_NEWHOPE PQPAKE_PROTO_CAKE_NEWHOPE512
#elif (CRYPTO_N==1024)
#define PQPAKE_PROTO_CAKE_NEWHOPE PQPAKE_PROTO_CAKE_NEWHOPE1024
#endif


/**
 * Generate the final secret from the CAKE protocol parameters
 *
 * @param final_secret output buffer
 * @param ssid Common session ID
 * @param epk Alice's encrypted public key. Size is PQPAKE_EPK_SIZE
 * @param ect Bob's encrypted cipher text. Size is PQPAKE_ECT_SIZE
 * @param secret Common Kyber caps/decaps secret.
 *               Size is PQPAKE_SHARED_SECRET_SIZE
 * @param alice_name Initiator agent name
 * @param alice_size Initiator agent name's size
 * @param bob_name Responder agent name
 * @param bob_size Responder agent name's size
 */
void cake_generate_final_secret(uint8_t* final_secret,
                                uint32_t ssid,
                                const uint8_t* epk,
                                const uint8_t* ect,
                                const uint8_t* secret,
                                const uint8_t* alice_name,
                                size_t alice_size,
                                const uint8_t* bob_name,
                                size_t bob_size) {
  size_t max_buffer_size = sizeof(ssid) + PQPAKE_EPK_SIZE + PQPAKE_ECT_SIZE +
                           PQPAKE_SHARED_SECRET_SIZE + alice_size +
                           bob_size;

  uint8_t base_string[max_buffer_size];

  uint8_t* head = base_string;

  memcpy(head, &ssid, sizeof(ssid));
  head += sizeof(ssid);

  memcpy(head, alice_name, alice_size);
  head += alice_size;

  memcpy(head, bob_name, bob_size);
  head += bob_size;

  memcpy(head, epk, PQPAKE_EPK_SIZE);
  head += PQPAKE_EPK_SIZE;

  memcpy(head, ect, PQPAKE_ECT_SIZE);
  head += PQPAKE_ECT_SIZE;

  memcpy(head, secret, PQPAKE_SHARED_SECRET_SIZE);
  head += PQPAKE_SHARED_SECRET_SIZE;

  int result_size = head - base_string;

  SHA256(base_string, result_size, final_secret);
  
}

cake_agent* cake_create_alice(uint32_t session_id,
                              const uint8_t* password,
                              size_t password_size,
                              const uint8_t* alice_name,
                              size_t alice_size) {
  pqpake_assert_constants();

  cake_agent* agent = malloc(sizeof(cake_agent));
  if (agent == NULL) {
    return NULL;
  }
  memset(agent, 0, sizeof(cake_agent));

  agent->session_id = session_id;
  pqpake_generate_symmetric_key(agent->sym_key, session_id, password,
                                password_size);

  agent->alice_size = alice_size;
  agent->alice_name = malloc(alice_size);
  if (agent->alice_name == NULL) {
    free(agent);
    return NULL;
  }
  memcpy(agent->alice_name, alice_name, alice_size);

  agent->bob_size = 0;
  agent->bob_name = NULL;

  return agent;
}

cake_agent* cake_create_bob(uint32_t session_id,
                            const uint8_t* password,
                            size_t password_size,
                            const uint8_t* bob_name,
                            size_t bob_size) {
  pqpake_assert_constants();

  cake_agent* agent = malloc(sizeof(cake_agent));
  if (agent == NULL) {
    return NULL;
  }
  memset(agent, 0, sizeof(cake_agent));

  agent->session_id = session_id;
  pqpake_generate_symmetric_key(agent->sym_key, session_id, password,
                                password_size);

  agent->alice_size = 0;
  agent->alice_name = NULL;

  agent->bob_size = bob_size;
  agent->bob_name = malloc(bob_size);
  if (agent->bob_name == NULL) {
    free(agent);
    return NULL;
  }
  memcpy(agent->bob_name, bob_name, bob_size);

  return agent;
}

void cake_free_agent(cake_agent* agent) {
  if (agent->alice_name != NULL) {
    free(agent->alice_name);
  }

  if (agent->bob_name != NULL) {
    free(agent->bob_name);
  }

  free(agent);
}

typedef struct cake_header {
  uint8_t step;
  uint8_t name_size;
  // the following {#message_size} bytes are the message (pk or ec)
  // the message size depends on the step :
  //   - step 1: CAKE_step1_MESSAGE_SIZE
  //   - step 2: CAKE_step2_MESSAGE_SIZE
  // the remaining {name_size} bytes are the name of the sender
} cake_header;

void cake_create_message_step1(cake_agent* alice,
                                uint8_t** out,
                                size_t* out_size) {
  /** alice cryptography */

  crypto_kem_keypair(alice->pk, alice->sk);
  if (pqpake_ic_publickey_encrypt(alice->sym_key, alice->pk, alice->epk) < 0) {
    *out_size = 0;
    *out = NULL;
    return;
  }

  /** alice --> bob : encrypted pk and alice's name */

  *out_size = sizeof(pqpake_header) + sizeof(cake_header) +
              CAKE_step1_MESSAGE_SIZE + alice->alice_size;
  *out = malloc(*out_size);
  if (*out == NULL) {
    *out_size = 0;
    return;
  }
  memset(*out, 0, *out_size);

  pqpake_header* pheader = (pqpake_header*)*out;
  pheader->protocol = PQPAKE_PROTO_CAKE_NEWHOPE;

  cake_header* cheader = (cake_header*)(*out + sizeof(pqpake_header));
  cheader->step = 1;
  cheader->name_size = alice->alice_size;

  uint8_t* epk = (uint8_t*)cheader + sizeof(cake_header);
  memcpy(epk, alice->epk, CAKE_step1_MESSAGE_SIZE);

  uint8_t* name = epk + CAKE_step1_MESSAGE_SIZE;
  memcpy(name, alice->alice_name, alice->alice_size);
}

void cake_create_message_step2(cake_agent* bob,
                                const uint8_t* in,
                                uint8_t** out,
                                size_t* out_size) {
  /** parsing incoming message */

  const pqpake_header* in_pheader = (pqpake_header*)in;
  if (in_pheader->protocol != PQPAKE_PROTO_CAKE_NEWHOPE) {
    *out_size = 0;
    *out = NULL;
    return;
  }

  const cake_header* in_cheader = (cake_header*)(in + sizeof(pqpake_header));
  if (in_cheader->step != 1) {
    *out_size = 0;
    *out = NULL;
    return;
  }

  const uint8_t* in_epk = (uint8_t*)in_cheader + sizeof(cake_header);
  if (pqpake_ic_publickey_decrypt(bob->sym_key, in_epk, bob->pk) < 0) {
    printf("cake_create_message_step2: pqpake_ic_publickey_decrypt failed\n");
    *out_size = 0;
    *out = NULL;
    return;
  }

  bob->alice_size = in_cheader->name_size;
  bob->alice_name = malloc(bob->alice_size);
  if (bob->alice_name == NULL) {
    *out_size = 0;
    *out = NULL;
    return;
  }
  const uint8_t* in_name = in_epk + CAKE_step1_MESSAGE_SIZE;
  memcpy(bob->alice_name, in_name, bob->alice_size);

  /** bob cryptography */

  uint8_t bob_ss[PQPAKE_SHARED_SECRET_SIZE] = {0};
  uint8_t bob_ct[PQPAKE_CT_SIZE] = {0};
  crypto_kem_enc(bob_ct, bob_ss, bob->pk);

  uint8_t ect[CAKE_step2_MESSAGE_SIZE] = {0};
  pqpake_ic_ciphertext_encrypt(bob->sym_key, bob_ct, ect);

  cake_generate_final_secret(bob->ss, bob->session_id, in_epk, ect, bob_ss,
                             bob->alice_name, bob->alice_size, bob->bob_name,
                             bob->bob_size);

  /** bob --> alice : encrypted ct and bob's name */

  *out_size = sizeof(pqpake_header) + sizeof(cake_header) +
              CAKE_step2_MESSAGE_SIZE + bob->bob_size;
  *out = malloc(*out_size);
  if (*out == NULL) {
    *out_size = 0;
    return;
  }
  memset(*out, 0, *out_size);

  pqpake_header* out_pheader = (pqpake_header*)*out;
  out_pheader->protocol = PQPAKE_PROTO_CAKE_NEWHOPE;

  cake_header* out_cheader = (cake_header*)(*out + sizeof(pqpake_header));
  out_cheader->step = 2;
  out_cheader->name_size = bob->bob_size;

  uint8_t* out_ect = (uint8_t*)out_cheader + sizeof(cake_header);
  memcpy(out_ect, ect, CAKE_step2_MESSAGE_SIZE);

  uint8_t* out_name = out_ect + CAKE_step2_MESSAGE_SIZE;
  memcpy(out_name, bob->bob_name, bob->bob_size);
}

void cake_create_message_step3(cake_agent* alice, const uint8_t* in) {
  const pqpake_header* pheader = (pqpake_header*)in;
  if (pheader->protocol != PQPAKE_PROTO_CAKE_NEWHOPE) {
    return;
  }

  const cake_header* cheader = (cake_header*)(in + sizeof(pqpake_header));
  if (cheader->step != 2) {
    return;
  }

  const uint8_t* ect = (uint8_t*)cheader + sizeof(cake_header);
  uint8_t alice_ct[PQPAKE_CT_SIZE] = {0};
  pqpake_ic_ciphertext_decrypt(alice->sym_key, ect, alice_ct);

  alice->bob_size = cheader->name_size;
  alice->bob_name = malloc(alice->bob_size);
  if (alice->bob_name == NULL) {
    return;
  }
  const uint8_t* name = ect + CAKE_step2_MESSAGE_SIZE;
  memcpy(alice->bob_name, name, alice->bob_size);

  uint8_t alice_ss[PQPAKE_SHARED_SECRET_SIZE];
  crypto_kem_dec(alice_ss, alice_ct, alice->sk);

  cake_generate_final_secret(alice->ss, alice->session_id, alice->epk, ect,
                             alice_ss, alice->alice_name, alice->alice_size,
                             alice->bob_name, alice->bob_size);
}

const uint8_t* cake_get_shared_secret(const cake_agent* agent) {
  return agent->ss;
}
