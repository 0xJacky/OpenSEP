#include "open_secure_rom/crypto_fault.h"

#include "open_secure_rom/bignum.h"
#include "open_secure_rom/runtime.h"

void sep_cc_fault_canary_set(
    sep_u8 output[16],
    const sep_u8 canary[16],
    sep_size_t input_length,
    const sep_u8 *left,
    const sep_u8 *right
) {
    if (input_length == 0) {
        sep_fatal_wait_loop();
    }
    for (sep_size_t index = 0; index < 16; ++index) {
        const sep_size_t input_index = index % input_length;
        output[index] = left[input_index] ^ right[input_index] ^ canary[index];
    }
    for (sep_size_t index = 16; index < input_length; ++index) {
        const sep_size_t output_index = index % 16;
        output[output_index] = left[index] ^ right[index] ^ output[output_index];
    }
}

int sep_constant_time_compare_checked(
    sep_size_t length,
    const void *left,
    const void *right
) {
    if (left == NULL || right == NULL) {
        sep_fatal_wait_loop();
    }
    return sep_cc_cmp_safe(length, left, right);
}

sep_size_t sep_sizeof_struct_ccec_full_ctx(void) {
    return 16;
}
