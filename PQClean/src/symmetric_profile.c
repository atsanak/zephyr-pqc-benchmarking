#include "symmetric_profile.h"

#include <string.h>

static symmetric_profile_totals_t g_symmetric_totals;

void symmetric_profile_reset(void)
{
    memset(&g_symmetric_totals, 0, sizeof(g_symmetric_totals));
}

void symmetric_profile_add_sha2(uint64_t cycles)
{
    g_symmetric_totals.sha2_cycles += cycles;
}

void symmetric_profile_add_sha3_keccak(uint64_t cycles)
{
    g_symmetric_totals.sha3_keccak_cycles += cycles;
}

void symmetric_profile_add_aes(uint64_t cycles)
{
    g_symmetric_totals.aes_cycles += cycles;
}

void symmetric_profile_get_totals(symmetric_profile_totals_t *totals)
{
    if (!totals) {
        return;
    }

    *totals = g_symmetric_totals;
}
