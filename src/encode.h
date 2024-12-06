#include <stdint.h>
#ifndef PQPAKE_IC_ENCODE_H
#define PQPAKE_IC_ENCODE_H


void pqpake_ic_encode(const uint8_t* input, uint8_t* output);


void pqpake_ic_decode(uint8_t* input, uint8_t* output);


int pqpake_ic_value_is_not_in_range(const uint8_t* value);

#endif  // PQPAKE_IC_ENCODE_H
