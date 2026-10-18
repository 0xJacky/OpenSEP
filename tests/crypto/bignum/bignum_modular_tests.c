#include "open_secure_rom/bignum_modular.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sep_u64 random_state = UINT64_C(0x6a09e667f3bcc909);

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    abort();
}

static sep_u64 next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static sep_cczp_t *init_default_prime(
    sep_u64 *storage,
    sep_u64 prime
) {
    memset(storage, 0, SEP_CCZP_STORAGE_WORDS(1) * sizeof(*storage));
    sep_cczp_t *zp = (sep_cczp_t *)(void *)storage;
    zp->n = 1;
    ((sep_u64 *)(void *)(zp + 1))[0] = prime;
    assert(sep_cczp_init_ws(NULL, zp) == 0);
    return zp;
}

static sep_cczp_t *init_montgomery_prime(
    sep_u64 *storage,
    sep_u64 prime
) {
    memset(storage, 0, SEP_CCZP_STORAGE_WORDS(1) * sizeof(*storage));
    sep_cczp_t *zp = (sep_cczp_t *)(void *)storage;
    assert(sep_cczp_mm_init_ws(NULL, zp, 1, &prime) == 0);
    return zp;
}

static sep_u64 native_div2_mod(sep_u64 value, sep_u64 prime) {
    return (value + ((value & 1) != 0 ? prime : 0)) >> 1;
}

static void test_context_layout(void) {
    sep_u64 storage[SEP_CCZP_STORAGE_WORDS(1)];
    sep_cczp_t *zp = init_default_prime(storage, 97);
    const sep_u64 *prime = sep_cczp_prime(zp);
    assert(zp->bitlen == 7);
    assert(prime[0] == 97);
    assert(prime[0] * prime[1] == UINT64_MAX);
    assert(prime[2] == 35);

    sep_u64 invalid_storage[SEP_CCZP_STORAGE_WORDS(1)] = { 0 };
    sep_cczp_t *invalid = (sep_cczp_t *)(void *)invalid_storage;
    invalid->n = 1;
    ((sep_u64 *)(void *)(invalid + 1))[0] = 98;
    assert(sep_cczp_init_ws(NULL, invalid) == -7);
}

static void test_divmod_golden(void) {
    const sep_u64 ten = 10;
    const sep_u64 three = 3;
    sep_u64 small_quotient;
    sep_u64 small_remainder;
    sep_ccn_divmod_ws(
        NULL,
        1,
        &ten,
        1,
        &small_quotient,
        1,
        &small_remainder,
        &three
    );
    assert(small_quotient == 3);
    assert(small_remainder == 1);
    const sep_u64 dividend[3] = {
        UINT64_C(0xdeadbeefcafebabe),
        UINT64_C(0x0123456789abcdef),
        UINT64_C(0xfedcba9876543210),
    };
    const sep_u64 divisor[2] = {
        UINT64_C(0x1111111111111111),
        UINT64_C(0x1234567890abcdef),
    };
    const sep_u64 expected_quotient[3] = {
        UINT64_C(0x00000007bde000cb),
        UINT64_C(0x000000000000000e),
        0,
    };
    const sep_u64 expected_remainder[2] = {
        UINT64_C(0x56253667c6963243),
        UINT64_C(0x01b3b5f6ba40926f),
    };
    sep_u64 quotient[3];
    sep_u64 remainder[2];
    sep_u64 self_quotient[2];
    sep_u64 self_remainder[2];
    sep_u64 direct_difference[2];
    assert(sep_ccn_sub(2, direct_difference, divisor, divisor) == 0);
    assert(direct_difference[0] == 0 && direct_difference[1] == 0);
    sep_ccn_divmod_ws(
        NULL,
        2,
        divisor,
        2,
        self_quotient,
        2,
        self_remainder,
        divisor
    );
    assert(self_quotient[0] == 1 && self_quotient[1] == 0);
    assert(self_remainder[0] == 0 && self_remainder[1] == 0);
    sep_ccn_divmod_ws(
        NULL,
        3,
        dividend,
        3,
        quotient,
        2,
        remainder,
        divisor
    );
    assert(memcmp(quotient, expected_quotient, sizeof(quotient)) == 0);
    assert(memcmp(remainder, expected_remainder, sizeof(remainder)) == 0);
}

static void test_divmod_properties(void) {
    for (sep_size_t iteration = 0; iteration < 2000; ++iteration) {
        const sep_u64 divisor = (next_random() | 1);
        const sep_u64 dividend[2] = { next_random(), next_random() };
        sep_u64 quotient[2];
        sep_u64 remainder;
        sep_ccn_divmod_ws(
            NULL,
            2,
            dividend,
            2,
            quotient,
            1,
            &remainder,
            &divisor
        );
        const unsigned __int128 native =
            ((unsigned __int128)dividend[1] << 64) | dividend[0];
        const unsigned __int128 expected_quotient = native / divisor;
        assert(quotient[0] == (sep_u64)expected_quotient);
        assert(quotient[1] == (sep_u64)(expected_quotient >> 64));
        assert(remainder == (sep_u64)(native % divisor));
    }
}

static void test_default_field_properties(void) {
    sep_u64 storage[SEP_CCZP_STORAGE_WORDS(1)];
    sep_cczp_t *zp = init_default_prime(storage, 97);
    for (sep_u64 x = 0; x < 97; ++x) {
        sep_u64 negated;
        sep_u64 halved;
        sep_cczp_negate(zp, &negated, &x);
        assert(negated == (x == 0 ? 0 : 97 - x));
        sep_cczp_div2_ws(NULL, zp, &halved, &x);
        assert(halved == native_div2_mod(x, 97));
        for (sep_u64 y = 0; y < 97; ++y) {
            sep_u64 result;
            sep_cczp_add_ws(NULL, zp, &result, &x, &y);
            assert(result == (x + y) % 97);
            sep_cczp_sub_ws(NULL, zp, &result, &x, &y);
            assert(result == (x + 97 - y) % 97);
            sep_cczp_mul_ws(NULL, zp, &result, &x, &y);
            assert(result == (x * y) % 97);
        }
    }

    const sep_u64 base = 5;
    const sep_u64 exponent = 117;
    sep_u64 powered;
    assert(sep_cczp_power_fast_ws(NULL, zp, &powered, &base, &exponent) == 0);
    assert(powered == 77);

    const sep_u64 wide[3] = {
        UINT64_C(0xfedcba9876543210),
        UINT64_C(0x0123456789abcdef),
        UINT64_C(0x5555555555555555),
    };
    sep_u64 reduced;
    sep_cczp_modn_ws(NULL, zp, &reduced, 3, wide);
    sep_u64 expected = wide[2] % 97;
    for (sep_size_t i = 0; i < 64; ++i) {
        expected = (expected * 2) % 97;
    }
    expected = (expected + wide[1] % 97) % 97;
    for (sep_size_t i = 0; i < 64; ++i) {
        expected = (expected * 2) % 97;
    }
    expected = (expected + wide[0] % 97) % 97;
    assert(reduced == expected);
}

static void test_inverse_and_sqrt(void) {
    sep_u64 storage[SEP_CCZP_STORAGE_WORDS(1)];
    sep_cczp_t *zp = init_default_prime(storage, 97);
    for (sep_u64 value = 1; value < 97; ++value) {
        sep_u64 inverse;
        assert(sep_cczp_inv_ws(NULL, zp, &inverse, &value) == 0);
        assert((inverse * value) % 97 == 1);
    }
    sep_u64 zero = 0;
    sep_u64 output = UINT64_MAX;
    assert(sep_cczp_inv_ws(NULL, zp, &output, &zero) == -7);
    assert(output == 0);

    for (sep_u64 value = 0; value < 97; ++value) {
        int residue = 0;
        for (sep_u64 root = 0; root < 97; ++root) {
            residue |= (root * root) % 97 == value;
        }
        if (value != 0) {
            assert((sep_cczp_is_quadratic_residue_ws(NULL, zp, &value) == 0) ==
                   residue);
        }
        sep_u64 root;
        const int status = sep_cczp_sqrt_ws(NULL, zp, &root, &value);
        assert((status == 0) == residue);
        if (status == 0) {
            assert((root * root) % 97 == value);
        }
    }

    sep_u64 extended[SEP_CCZP_STORAGE_WORDS(1) + 1];
    sep_cczp_t *extended_zp = init_default_prime(extended, 97);
    extended[SEP_CCZP_STORAGE_WORDS(1)] = 95;
    const sep_u64 five = 5;
    sep_u64 inverse;
    assert(sep_cczp_inv_field_ws(NULL, extended_zp, &inverse, &five) == 0);
    assert(inverse == 39);

    const sep_u64 a = 5;
    const sep_u64 b = 7;
    sep_u64 updated;
    sep_cczp_inv_update_redc_ws(
        NULL,
        zp,
        &updated,
        &a,
        UINT64_MAX - 2,
        &b,
        11
    );
    sep_u64 expected = 62;
    for (sep_size_t i = 0; i < 31; ++i) {
        expected = native_div2_mod(expected, 97);
    }
    assert(updated == expected);
}

static void test_montgomery_properties(void) {
    sep_u64 storage[SEP_CCZP_STORAGE_WORDS(1)];
    sep_cczp_t *zp = init_montgomery_prime(storage, 97);
    for (sep_u64 x = 0; x < 97; ++x) {
        sep_u64 encoded;
        sep_u64 decoded;
        sep_cczp_to_ws(NULL, zp, &encoded, &x);
        sep_cczp_from_ws(NULL, zp, &decoded, &encoded);
        assert(decoded == x);
        for (sep_u64 y = 0; y < 97; ++y) {
            sep_u64 encoded_y;
            sep_u64 product;
            sep_cczp_to_ws(NULL, zp, &encoded_y, &y);
            sep_cczp_mul_ws(NULL, zp, &product, &encoded, &encoded_y);
            sep_cczp_from_ws(NULL, zp, &decoded, &product);
            assert(decoded == (x * y) % 97);
        }
    }
    const sep_u64 five = 5;
    sep_u64 encoded;
    sep_u64 inverse;
    sep_u64 decoded;
    sep_cczp_to_ws(NULL, zp, &encoded, &five);
    assert(sep_cczp_inv_ws(NULL, zp, &inverse, &encoded) == 0);
    sep_cczp_from_ws(NULL, zp, &decoded, &inverse);
    assert(decoded == 39);
}

static void test_p384_kats(void) {
    const sep_u64 prime[6] = {
        UINT64_C(0x00000000ffffffff),
        UINT64_C(0xffffffff00000000),
        UINT64_C(0xfffffffffffffffe),
        UINT64_C(0xffffffffffffffff),
        UINT64_C(0xffffffffffffffff),
        UINT64_C(0xffffffffffffffff),
    };
    const sep_u64 two[6] = { 2, 0, 0, 0, 0, 0 };
    const sep_u64 three[6] = { 3, 0, 0, 0, 0, 0 };
    const sep_u64 expected_inverse_two[6] = {
        UINT64_C(0x0000000080000000),
        UINT64_C(0x7fffffff80000000),
        UINT64_C(0xffffffffffffffff),
        UINT64_C(0xffffffffffffffff),
        UINT64_C(0xffffffffffffffff),
        UINT64_C(0x7fffffffffffffff),
    };
    sep_u64 two_montgomery[6];
    sep_u64 three_montgomery[6];
    sep_u64 product[6];
    sep_u64 affine[6];

    sep_u64 generic_storage[SEP_CCZP_STORAGE_WORDS(6)] = { 0 };
    sep_cczp_t *generic = (sep_cczp_t *)(void *)generic_storage;
    assert(sep_cczp_mm_init_ws(NULL, generic, 6, prime) == 0);
    sep_cczp_to_ws(NULL, generic, two_montgomery, two);
    sep_cczp_from_ws(NULL, generic, affine, two_montgomery);
    assert(memcmp(affine, two, sizeof(affine)) == 0);

    sep_ccn_p384_to_ws(NULL, NULL, two_montgomery, two);
    sep_ccn_p384_to_ws(NULL, NULL, three_montgomery, three);
    sep_ccn_p384_from_asm_ws(NULL, NULL, affine, two_montgomery);
    assert(memcmp(affine, two, sizeof(affine)) == 0);
    sep_ccn_p384_from_asm_ws(NULL, NULL, affine, three_montgomery);
    assert(memcmp(affine, three, sizeof(affine)) == 0);
    sep_ccn_p384_mul_asm_ws(
        NULL,
        NULL,
        product,
        two_montgomery,
        three_montgomery
    );
    sep_ccn_p384_from_asm_ws(NULL, NULL, affine, product);
    assert(affine[0] == 6);
    for (sep_size_t i = 1; i < 6; ++i) {
        assert(affine[i] == 0);
    }

    sep_u64 inverse[6];
    assert(sep_ccn_p384_inv_asm_ws(
        NULL,
        NULL,
        inverse,
        two_montgomery
    ) == 0);
    sep_ccn_p384_from_asm_ws(NULL, NULL, affine, inverse);
    assert(memcmp(affine, expected_inverse_two, sizeof(affine)) == 0);

    const sep_u64 zero[6] = { 0, 0, 0, 0, 0, 0 };
    assert(sep_ccn_p384_inv_asm_ws(NULL, NULL, inverse, zero) == -42);
}

int main(void) {
    test_context_layout();
    test_divmod_golden();
    test_divmod_properties();
    test_default_field_properties();
    test_inverse_and_sqrt();
    test_montgomery_properties();
    test_p384_kats();
    puts("bignum modular tests passed");
    return 0;
}
