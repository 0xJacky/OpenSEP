#include "open_secure_rom/bignum.h"
#include "open_secure_rom/ecc.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

enum { GCD_APPROXIMATION_SHIFT = 31 };

typedef struct test_rng {
    sep_ccrng_state_t base;
    sep_size_t requested;
    int status;
} test_rng_t;

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

static int generate(
    sep_ccrng_state_t *base,
    sep_size_t output_length,
    void *output
) {
    test_rng_t *rng = (test_rng_t *)base;
    rng->requested = output_length;
    for (sep_size_t index = 0; index < output_length; ++index) {
        ((sep_u8 *)output)[index] = (sep_u8)(0xa0 + index);
    }
    return rng->status;
}

static void test_gcd_approximation(void) {
    const sep_u64 u[3] = {
        UINT64_C(0x123456789abcdef0),
        UINT64_C(0xfedcba9876543210),
        UINT64_C(0x0000000000001234),
    };
    const sep_u64 v[3] = {
        UINT64_C(0x0fedcba987654321),
        UINT64_C(0x0123456789abcdef),
        UINT64_C(0x0000000000004321),
    };
    sep_u64 ua;
    sep_u64 va;
    sep_ccn_gcd_approximate(3, u, &ua, v, &va);
    assert(ua == UINT64_C(0x2469fdb91abcdef0));
    assert(va == UINT64_C(0x8642024687654321));
}

static void test_gcd_update(void) {
    sep_u64 storage[16];
    sep_cc_ws_t workspace = {
        .ctx = storage,
        .nunits = 16,
        .offset = 2,
    };
    const sep_u64 u[2] = {UINT64_C(0x80000000), 0};
    const sep_u64 v[2] = {UINT64_C(0x40000000), 0};
    sep_u64 result[2];

    assert(sep_ccn_gcd_update_ws(
        &workspace,
        2,
        result,
        u,
        2,
        v,
        (sep_u64)-1
    ) == 0);
    assert(result[0] == 1);
    assert(result[1] == 0);
    assert(workspace.offset == 2);

    assert(sep_ccn_gcd_update_ws(
        &workspace,
        2,
        result,
        u,
        (sep_u64)-1,
        v,
        0
    ) == 1);
    assert(result[0] == 1);
    assert(result[1] == 0);

    uint64_t state = UINT64_C(0x6a09e667f3bcc909);
    for (unsigned iteration = 0; iteration < 2000; ++iteration) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const sep_u64 left[2] = {state & UINT64_C(0x7fffffffffffffff), 0};
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const sep_u64 right[2] = {state & UINT64_C(0x7fffffffffffffff), 0};
        const int64_t f_signed = (int32_t)state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const int64_t g_signed = (int32_t)state;
        const __int128 combined =
            (__int128)left[0] * f_signed +
            (__int128)right[0] * g_signed;
        const unsigned __int128 magnitude = combined < 0
            ? (unsigned __int128)-combined
            : (unsigned __int128)combined;
        const unsigned __int128 expected =
            magnitude >> GCD_APPROXIMATION_SHIFT;

        const sep_u64 negative = sep_ccn_gcd_update_ws(
            &workspace,
            2,
            result,
            left,
            (sep_u64)f_signed,
            right,
            (sep_u64)g_signed
        );
        assert(negative == (combined < 0));
        assert(result[0] == (sep_u64)expected);
        assert(result[1] == (sep_u64)(expected >> 64));
        assert(workspace.offset == 2);
    }
}

static void test_random_bits(void) {
    test_rng_t rng = {
        .base = {.generate = generate},
        .requested = 0,
        .status = 0,
    };
    sep_u64 result[2] = {0, 0};

    assert(sep_ccn_random_bits(70, result, &rng.base) == 0);
    assert(rng.requested == 16);
    assert(result[1] == UINT64_C(0x0000000000000028));

    memset(result, 0, sizeof(result));
    assert(sep_ccn_random_bits_fips(63, result, &rng.base) == 0);
    assert(rng.requested == 12);
    assert(result[0] == UINT64_C(0x27a6a5a4a3a2a1a0));

    rng.status = -7;
    assert(sep_ccn_random_bits(64, result, &rng.base) == -7);
}

int main(void) {
    test_gcd_approximation();
    test_gcd_update();
    test_random_bits();
    return 0;
}
