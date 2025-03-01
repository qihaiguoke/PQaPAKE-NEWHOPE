#ifndef OMEGA_TRANSFORM_H
#define OMEGA_TRANSFORM_H

#include <stdint.h>
#include "constants.h"
#include "crypto_tools.h"

#define TOTAL_ROUNDS 4

typedef struct transcript{
    uint8_t *message[TOTAL_ROUNDS];
    size_t bytes[TOTAL_ROUNDS];
}transcript;

typedef struct omtransform_crs
{
    char salt0[SALT_LENGTH];
    char salt1[SALT_LENGTH];

    size_t current_round;
    transcript tr;
}omtransform_crs; 

typedef struct omtransform_client
{
    char *password;
    uint8_t pwfile[KEY_LENGTH];
    uint8_t symkey[KEY_LENGTH];
    uint8_t sharedkey[KEY_LENGTH];
    uint8_t mackey[KEY_LENGTH];

}omtransform_client;

typedef struct omtransform_server
{
    uint8_t pwfile[KEY_LENGTH];
    uint8_t pk[PQPAKE_PK_SIZE];
    uint8_t esk[PQPAKE_SK_SIZE+IV_LENGTH+AUTH_TAG_LENGTH];
    int esk_size;
    uint8_t symkey[KEY_LENGTH];
    uint8_t sharedkey[KEY_LENGTH];
    uint8_t mackey[KEY_LENGTH];
}omtransform_server;


void omtransform_init(char *password, omtransform_crs *crs, omtransform_client *client, omtransform_server *server);

void omtransform_free_crs(omtransform_crs *crs);

void upadte_transcript(omtransform_crs *crs, uint8_t *message, size_t bytes);

void omtransform_message_setp1(omtransform_crs *crs, omtransform_server *server, const uint8_t *ss);

void omtransform_message_setp2(omtransform_crs *crs, omtransform_client *client, const uint8_t *ss);

int omtransform_message_setp3(omtransform_crs *crs, omtransform_server *server);

void print_buffer(const uint8_t *buffer, int size);

#endif