#include "open_secure_rom/crypto_fault.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected crypto fault fatal path");
    __builtin_unreachable();
}

static void test_fault_canary(void) {
    static const sep_u8 canary[16] = {
        0xea, 0xc5, 0x4a, 0x7c, 0x9f, 0x28, 0xdf, 0x10,
        0xb6, 0xe9, 0x3e, 0xb9, 0x1c, 0xd3, 0x3a, 0xc5,
    };
    sep_u8 left[20];
    sep_u8 right[20];
    for (sep_size_t index = 0; index < 20; ++index) {
        left[index] = (sep_u8)index;
        right[index] = (sep_u8)(index * 3);
    }
    sep_u8 output[16];
    sep_cc_fault_canary_set(output, canary, 20, left, right);
    for (sep_size_t index = 0; index < 16; ++index) {
        sep_u8 expected = left[index] ^ right[index] ^ canary[index];
        if (index < 4) {
            expected ^= left[index + 16] ^ right[index + 16];
        }
        assert(output[index] == expected);
    }
}

int main(void) {
    test_fault_canary();
    const sep_u8 left[] = {1, 2, 3};
    const sep_u8 equal[] = {1, 2, 3};
    const sep_u8 different[] = {1, 2, 4};
    assert(sep_constant_time_compare_checked(3, left, equal) == 0);
    assert(sep_constant_time_compare_checked(3, left, different) == 1);
    assert(sep_sizeof_struct_ccec_full_ctx() == 16);
}
