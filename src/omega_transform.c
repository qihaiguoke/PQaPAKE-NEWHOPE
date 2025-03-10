#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "constants.h"
#include "publickey.h"
#include "crypto_tools.h"
#include "omega_transform.h"
#include "api.h"

#if (CRYPTO_N == 512)
#define HASH SHA256
#elif (CRYPTO_N == 1024)
#define HASH SHA512
#endif

void omtransform_init(char *password, omtransform_crs *crs, omtransform_client *client, omtransform_server *server)
{
    crs->current_round = 0;
    generate_salt(crs->salt0, SALT_LENGTH);
    generate_salt(crs->salt1, SALT_LENGTH);

    client->password = password;
    int pwsize = strlen(password);
    derive_key((uint8_t *)password, pwsize, crs->salt0, server->pwfile);

    uint8_t sk[PQPAKE_SK_SIZE];
    crypto_kem_keypair(server->pk, sk);

    uint8_t key[KEY_LENGTH];
    derive_key((uint8_t *)password, pwsize, crs->salt1, key);
    ae_encrypt(key, sk, PQPAKE_SK_SIZE, server->esk, &server->esk_size);
}


void omtransform_free_crs(omtransform_crs *crs)
{
    for (int i = 0; i < crs->current_round; ++i)
        free(crs->tr.message[i]);
    free(crs);
}

void upadte_transcript(omtransform_crs *crs, uint8_t *message, size_t bytes)
{
    crs->tr.bytes[crs->current_round] = bytes;
    crs->tr.message[crs->current_round] = message;
    ++crs->current_round;
}

void omtransform_message_setp1(omtransform_crs *crs, omtransform_server *server, const uint8_t *ss)
{
    uint8_t dk[KEY_LENGTH*2];
    HASH(ss, PQPAKE_SHARED_SECRET_SIZE, dk);
    memcpy(server->symkey, dk, KEY_LENGTH);
    memcpy(server->sharedkey, dk + KEY_LENGTH, KEY_LENGTH);

    int out_size;
    uint8_t eesk[AUTH_TAG_LENGTH + IV_LENGTH + server->esk_size + 16];
    ae_encrypt(server->symkey, server->esk, server->esk_size, eesk, &out_size);

    int round = crs->current_round;
    crs->tr.message[round] = malloc(PQPAKE_CT_SIZE + out_size);

    memcpy(crs->tr.message[round], eesk, out_size);
    crypto_kem_enc(crs->tr.message[round] + out_size, server->mackey, server->pk);

    crs->tr.bytes[round] = out_size + PQPAKE_CT_SIZE;
}

void omtransform_message_setp2(omtransform_crs *crs, omtransform_client *client, const uint8_t *ss)
{
    
    uint8_t dk[KEY_LENGTH*2];
    HASH(ss, PQPAKE_SHARED_SECRET_SIZE, dk);
    memcpy(client->symkey, dk, KEY_LENGTH);
    memcpy(client->sharedkey, dk + KEY_LENGTH, KEY_LENGTH);
;

    int round = crs->current_round;
    uint8_t esk[AUTH_TAG_LENGTH + IV_LENGTH + PQPAKE_SK_SIZE];
    int cipher_size = crs->tr.bytes[round] - PQPAKE_CT_SIZE;
    int esk_size;
    ae_decrypt(client->symkey, crs->tr.message[round], cipher_size, esk, &esk_size);

    uint8_t key[KEY_LENGTH];
    uint8_t sk[PQPAKE_SK_SIZE];
    derive_key((uint8_t *)client->password, strlen(client->password), crs->salt1, key);
    ae_decrypt(key, esk, esk_size, sk, NULL);

    crypto_kem_dec(client->mackey, crs->tr.message[round] + cipher_size, sk);
    round = ++(crs->current_round);
    crs->tr.bytes[round] = HMAC_LENGTH;
    crs->tr.message[round] = malloc(HMAC_LENGTH);
    transcript_hmac(crs->tr.message, crs->tr.bytes, crs->current_round, client->mackey, KEY_LENGTH, crs->tr.message[round]);
}

int omtransform_message_setp3(omtransform_crs *crs, omtransform_server *server)
{
    int round = crs->current_round;
    uint8_t tr_hmac[HMAC_LENGTH];
    transcript_hmac(crs->tr.message, crs->tr.bytes, round, server->mackey, KEY_LENGTH, tr_hmac);
    int valid = memcmp(tr_hmac, crs->tr.message[round], HMAC_LENGTH);
    if (valid != 0)
        printf("omtransform_message_step3: mac of transcripts is invalid!\n");
    return valid;
}

void print_buffer(const uint8_t *buffer, int size)
{
    for (int i = 0; i < size; i++)
    {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}