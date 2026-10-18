#include "open_secure_rom/bignum.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

int main(void) {
    const sep_u64 left[2] = {UINT64_MAX, 7};
    const sep_u64 right[2] = {2, 3};
    sep_u64 result[4];
    assert(sep_ccn_add(2, result, left, right) == 0);
    assert(result[0] == 1 && result[1] == 11);
    assert(sep_ccn_sub(2, result, left, right) == 0);
    assert(result[0] == UINT64_MAX - 2 && result[1] == 4);

    const sep_u64 small_left[2] = {1, 2};
    const sep_u64 small_right[2] = {3, 4};
    sep_ccn_mul(2, result, small_left, small_right);
    assert(result[0] == 3 && result[1] == 10);
    assert(result[2] == 8 && result[3] == 0);

    sep_u64 conditional[2];
    assert(sep_ccn_cond_add(2, 0, conditional, small_left, small_right) == 0);
    assert(conditional[0] == 1 && conditional[1] == 2);
    assert(sep_ccn_cond_add(2, 1, conditional, small_left, small_right) == 0);
    assert(conditional[0] == 4 && conditional[1] == 6);
    sep_ccn_cond_swap(2, 1, conditional, result);
    assert(conditional[0] == 3 && result[0] == 4);

    const sep_u64 encoded_limbs[2] = {
        0x0123456789abcdefULL,
        0xfedcba9876543210ULL,
    };
    static const sep_u8 encoded[16] = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    sep_u8 bytes[18];
    assert(sep_ccn_write_uint_padded(2, encoded_limbs, 18, bytes) == 2);
    assert(bytes[0] == 0 && bytes[1] == 0);
    for (sep_size_t index = 0; index < 16; ++index) {
        assert(bytes[index + 2] == encoded[index]);
    }
    sep_u64 decoded[2];
    assert(sep_ccn_read_uint(2, decoded, 16, encoded) == 0);
    assert(decoded[0] == encoded_limbs[0]);
    assert(decoded[1] == encoded_limbs[1]);

    sep_u8 short_output[8];
    sep_ccn_write_uint_internal(2, encoded_limbs, 8, short_output);
    for (sep_size_t index = 0; index < 8; ++index) {
        assert(short_output[index] == encoded[index]);
    }

    sep_u64 shifted[2];
    sep_ccn_shift_right_multi(2, shifted, encoded_limbs, 68);
    assert(shifted[0] == (encoded_limbs[1] >> 4));
    assert(shifted[1] == 0);
    sep_ccn_shift_left(2, shifted, encoded_limbs, 4);
    assert(shifted[0] == encoded_limbs[0] << 4);
    assert(shifted[1] == ((encoded_limbs[1] << 4) |
        (encoded_limbs[0] >> 60)));

    assert(sep_ccn_bitlen(2, encoded_limbs) == 128);
    assert(sep_ccn_cmpn_public_value(2, encoded_limbs, 1, encoded_limbs) > 0);
    assert(sep_cc_cmp_safe(16, encoded, encoded) == 0);
    assert(sep_cc_cmp_safe(0, encoded, encoded) == 1);
}
