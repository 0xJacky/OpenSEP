#include "open_secure_rom/bignum.h"

#include "open_secure_rom/crypto_workspace.h"
#include "open_secure_rom/ecc.h"
#include "open_secure_rom/runtime.h"

enum {
    LIMB_BITS = 64,
    GCD_APPROXIMATION_SHIFT = 31,
};

static sep_u64 nonzero_mask(sep_u64 value) {
    return (sep_u64)0 - (sep_u64)(value != 0);
}

void sep_ccn_gcd_approximate(
    sep_size_t limb_count,
    const sep_u64 *u,
    sep_u64 *u_approximation,
    const sep_u64 *v,
    sep_u64 *v_approximation
) {
    sep_u64 ua = u[limb_count - 1];
    sep_u64 va = v[limb_count - 1];

    for (sep_size_t index = limb_count - 1; index > 0; --index) {
        sep_size_t leading_zeroes =
            (sep_size_t)__builtin_clzll(ua | va | 1);
        sep_u64 populated = nonzero_mask(ua | va);
        sep_size_t shift = leading_zeroes + ((ua | va) >> 63);
        shift = (LIMB_BITS - shift) & (sep_size_t)populated;
        ua = (ua << leading_zeroes) | (u[index - 1] >> shift);
        va = (va << leading_zeroes) | (v[index - 1] >> shift);
    }

    *u_approximation =
        (ua & UINT64_C(0xffffffff80000000)) |
        (u[0] & UINT64_C(0x000000007fffffff));
    *v_approximation =
        (va & UINT64_C(0xffffffff80000000)) |
        (v[0] & UINT64_C(0x000000007fffffff));
}

static void set_extended(
    sep_size_t limb_count,
    sep_u64 *destination,
    const sep_u64 *source
) {
    for (sep_size_t index = 0; index < limb_count; ++index) {
        destination[index] = source[index];
    }
    destination[limb_count] = 0;
}

sep_u64 sep_ccn_gcd_update_ws(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *u,
    sep_u64 f,
    const sep_u64 *v,
    sep_u64 g
) {
    sep_size_t checkpoint = workspace->offset;
    sep_u64 *u_product = sep_cc_ws_alloc(workspace, limb_count + 1);
    sep_u64 *v_product = sep_cc_ws_alloc(workspace, limb_count + 1);
    sep_u64 f_negative = f >> 63;
    sep_u64 g_negative = g >> 63;

    set_extended(limb_count, u_product, u);
    sep_ccn_cond_neg(limb_count + 1, f_negative, u_product, u_product);
    sep_u64 f_mask = (sep_u64)0 - f_negative;
    f = (f ^ f_mask) + f_negative;

    set_extended(limb_count, v_product, v);
    sep_ccn_cond_neg(limb_count + 1, g_negative, v_product, v_product);
    sep_u64 g_mask = (sep_u64)0 - g_negative;
    g = (g ^ g_mask) + g_negative;

    (void)sep_ccn_mul1_asm(
        limb_count + 1,
        u_product,
        u_product,
        f
    );
    (void)sep_ccn_addmul1(
        limb_count + 1,
        u_product,
        v_product,
        g
    );

    sep_u64 result_negative = u_product[limb_count] >> 63;
    sep_ccn_cond_neg(
        limb_count + 1,
        result_negative,
        u_product,
        u_product
    );
    sep_ccn_shift_right(
        limb_count + 1,
        u_product,
        u_product,
        GCD_APPROXIMATION_SHIFT
    );
    for (sep_size_t index = 0; index < limb_count; ++index) {
        result[index] = u_product[index];
    }

    workspace->offset = checkpoint;
    return result_negative;
}

static void mask_last_limb(
    sep_size_t bit_count,
    sep_u64 *result
) {
    sep_size_t limb_count = (bit_count + LIMB_BITS - 1) / LIMB_BITS;
    sep_size_t last_limb_bits = bit_count & (LIMB_BITS - 1);
    if (last_limb_bits == 0) {
        last_limb_bits = LIMB_BITS;
    }
    result[limb_count - 1] &= UINT64_MAX >> (LIMB_BITS - last_limb_bits);
}

int sep_ccn_random_bits(
    sep_size_t bit_count,
    sep_u64 *result,
    sep_ccrng_state_t *rng
) {
    sep_size_t limb_count = (bit_count + LIMB_BITS - 1) / LIMB_BITS;
    int status = rng->generate(rng, limb_count * sizeof(sep_u64), result);
    if (status == 0) {
        mask_last_limb(bit_count, result);
    }
    return status;
}

int sep_ccn_random_bits_fips(
    sep_size_t bit_count,
    sep_u64 *result,
    sep_ccrng_state_t *rng
) {
    sep_size_t limb_count = (bit_count + LIMB_BITS - 1) / LIMB_BITS;
    sep_size_t byte_count = limb_count * sizeof(sep_u64);
    int status;

    if (byte_count < 12) {
        sep_u8 temporary[12] = {0};
        status = rng->generate(rng, sizeof(temporary), temporary);
        sep_memmove(result, temporary, byte_count);
        sep_memzero(temporary, sizeof(temporary));
    } else {
        status = rng->generate(rng, byte_count, result);
    }

    if (status == 0) {
        mask_last_limb(bit_count, result);
    }
    return status;
}
