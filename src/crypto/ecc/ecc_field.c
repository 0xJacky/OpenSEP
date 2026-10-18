#include "ecc_internal.h"

static const sep_u64 p384_prime[ECC_P384_LIMBS] = {
    UINT64_C(0x00000000ffffffff), UINT64_C(0xffffffff00000000),
    UINT64_C(0xfffffffffffffffe), UINT64_C(0xffffffffffffffff),
    UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff),
};

static const sep_u64 p384_r2[ECC_P384_LIMBS] = {
    UINT64_C(0xfffffffe00000001), UINT64_C(0x0000000200000000),
    UINT64_C(0xfffffffe00000000), UINT64_C(0x0000000200000000),
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
};

static const sep_u64 field_one[ECC_P384_LIMBS] = { 1, 0, 0, 0, 0, 0 };

static int compare_words(const sep_u64 *left, const sep_u64 *right) {
    for (sep_size_t i = ECC_P384_LIMBS; i != 0; --i) {
        if (left[i - 1] > right[i - 1]) {
            return 1;
        }
        if (left[i - 1] < right[i - 1]) {
            return -1;
        }
    }
    return 0;
}

static sep_u64 subtract_words(
    sep_u64 *result,
    const sep_u64 *left,
    const sep_u64 *right
) {
    sep_u64 borrow = 0;
    for (sep_size_t i = 0; i < ECC_P384_LIMBS; ++i) {
        const sep_u64 source = left[i];
        const unsigned __int128 subtrahend =
            (unsigned __int128)right[i] + borrow;
        result[i] = source - (sep_u64)subtrahend;
        borrow = (unsigned __int128)source < subtrahend;
    }
    return borrow;
}

void open_secure_rom_fe_copy(sep_u64 *result, const sep_u64 *value) {
    for (sep_size_t i = 0; i < ECC_P384_LIMBS; ++i) {
        result[i] = value[i];
    }
}

void open_secure_rom_fe_zero(sep_u64 *result) {
    for (sep_size_t i = 0; i < ECC_P384_LIMBS; ++i) {
        result[i] = 0;
    }
}

int open_secure_rom_fe_is_zero(const sep_u64 *value) {
    sep_u64 aggregate = 0;
    for (sep_size_t i = 0; i < ECC_P384_LIMBS; ++i) {
        aggregate |= value[i];
    }
    return aggregate == 0;
}

int open_secure_rom_fe_equal(const sep_u64 *left, const sep_u64 *right) {
    return compare_words(left, right) == 0;
}

void open_secure_rom_fe_add(
    sep_u64 *result,
    const sep_u64 *left,
    const sep_u64 *right
) {
    sep_u64 temporary[ECC_P384_LIMBS + 1];
    sep_u64 carry = 0;
    for (sep_size_t i = 0; i < ECC_P384_LIMBS; ++i) {
        const unsigned __int128 sum =
            (unsigned __int128)left[i] + right[i] + carry;
        temporary[i] = (sep_u64)sum;
        carry = (sep_u64)(sum >> 64);
    }
    temporary[ECC_P384_LIMBS] = carry;
    if (carry != 0 || compare_words(temporary, p384_prime) >= 0) {
        const sep_u64 borrow = subtract_words(temporary, temporary, p384_prime);
        temporary[ECC_P384_LIMBS] -= borrow;
    }
    open_secure_rom_fe_copy(result, temporary);
}

void open_secure_rom_fe_sub(
    sep_u64 *result,
    const sep_u64 *left,
    const sep_u64 *right
) {
    const sep_u64 borrow = subtract_words(result, left, right);
    if (borrow != 0) {
        sep_u64 carry = 0;
        for (sep_size_t i = 0; i < ECC_P384_LIMBS; ++i) {
            const unsigned __int128 sum =
                (unsigned __int128)result[i] + p384_prime[i] + carry;
            result[i] = (sep_u64)sum;
            carry = (sep_u64)(sum >> 64);
        }
    }
}

void open_secure_rom_fe_neg(sep_u64 *result, const sep_u64 *value) {
    if (open_secure_rom_fe_is_zero(value)) {
        open_secure_rom_fe_zero(result);
    } else {
        (void)subtract_words(result, p384_prime, value);
    }
}

void open_secure_rom_fe_mul(
    sep_u64 *result,
    const sep_u64 *left,
    const sep_u64 *right
) {
    sep_u64 left_montgomery[ECC_P384_LIMBS];
    sep_u64 right_montgomery[ECC_P384_LIMBS];
    sep_u64 product[ECC_P384_LIMBS];
    sep_ccn_mulmod_p384(left_montgomery, left, p384_r2);
    sep_ccn_mulmod_p384(right_montgomery, right, p384_r2);
    sep_ccn_mulmod_p384(product, left_montgomery, right_montgomery);
    sep_ccn_mulmod_p384(result, product, field_one);
}

void open_secure_rom_fe_sqr(sep_u64 *result, const sep_u64 *value) {
    open_secure_rom_fe_mul(result, value, value);
}

static void power(sep_u64 *result, const sep_u64 *base, const sep_u64 *exponent) {
    sep_u64 accumulator[ECC_P384_LIMBS];
    sep_u64 factor[ECC_P384_LIMBS];
    open_secure_rom_fe_copy(accumulator, field_one);
    open_secure_rom_fe_copy(factor, base);
    for (sep_size_t bit = 0; bit < 384; ++bit) {
        if (((exponent[bit >> 6] >> (bit & 63)) & 1) != 0) {
            open_secure_rom_fe_mul(accumulator, accumulator, factor);
        }
        if (bit + 1 < 384) {
            open_secure_rom_fe_sqr(factor, factor);
        }
    }
    open_secure_rom_fe_copy(result, accumulator);
}

void open_secure_rom_fe_inv(sep_u64 *result, const sep_u64 *value) {
    sep_u64 exponent[ECC_P384_LIMBS];
    open_secure_rom_fe_copy(exponent, p384_prime);
    (void)sep_ccn_sub1(ECC_P384_LIMBS, exponent, exponent, 2);
    power(result, value, exponent);
}

int open_secure_rom_fe_sqrt(sep_u64 *result, const sep_u64 *value) {
    sep_u64 exponent[ECC_P384_LIMBS];
    sep_u64 check[ECC_P384_LIMBS];
    open_secure_rom_fe_copy(exponent, p384_prime);
    (void)sep_ccn_add1(ECC_P384_LIMBS, exponent, exponent, 1);
    (void)sep_ccn_shift_right(ECC_P384_LIMBS, exponent, exponent, 2);
    power(result, value, exponent);
    open_secure_rom_fe_sqr(check, result);
    return open_secure_rom_fe_equal(check, value) ? 0 : ECC_PARAMETER_ERROR;
}
