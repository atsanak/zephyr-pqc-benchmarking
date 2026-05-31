#ifndef SYMMETRIC_PROFILE_H
#define SYMMETRIC_PROFILE_H

#include <stdint.h>

typedef struct {
    uint64_t sha2_cycles;
    uint64_t sha3_keccak_cycles;
    uint64_t aes_cycles;
} symmetric_profile_totals_t;

void symmetric_profile_reset(void);
void symmetric_profile_add_sha2(uint64_t cycles);
void symmetric_profile_add_sha3_keccak(uint64_t cycles);
void symmetric_profile_add_aes(uint64_t cycles);
void symmetric_profile_get_totals(symmetric_profile_totals_t *totals);

#endif // SYMMETRIC_PROFILE_H
