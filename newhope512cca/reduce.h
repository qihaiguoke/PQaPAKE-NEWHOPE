#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

uint16_t montgomery_reduce(uint32_t a);

#define BARRETT_BITS  26
#define MONT_POW 18

uint16_t barrett_reduce(uint32_t a);

#endif
