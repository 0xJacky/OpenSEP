#ifndef OPEN_SECURE_ROM_CRYPTO_FAULT_H
#define OPEN_SECURE_ROM_CRYPTO_FAULT_H

#include "open_secure_rom/types.h"

void sep_cc_fault_canary_set(
    sep_u8 output[16],
    const sep_u8 canary[16],
    sep_size_t input_length,
    const sep_u8 *left,
    const sep_u8 *right
);
int sep_constant_time_compare_checked(
    sep_size_t length,
    const void *left,
    const void *right
);
sep_size_t sep_sizeof_struct_ccec_full_ctx(void);

#endif
