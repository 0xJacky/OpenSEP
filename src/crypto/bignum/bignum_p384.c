#include "open_secure_rom/bignum_modular.h"

#define P384_LIMBS 6u
#define P384_INVERSE_FAILURE (-42)

static const sep_u64 p384_prime[P384_LIMBS] = {
    UINT64_C(0x00000000ffffffff),
    UINT64_C(0xffffffff00000000),
    UINT64_C(0xfffffffffffffffe),
    UINT64_C(0xffffffffffffffff),
    UINT64_C(0xffffffffffffffff),
    UINT64_C(0xffffffffffffffff),
};

static sep_cczp_t *make_p384_context(
    sep_u64 storage[SEP_CCZP_STORAGE_WORDS(P384_LIMBS)]
) {
    sep_cczp_t *zp = (sep_cczp_t *)(void *)storage;
    zp->n = P384_LIMBS;
    zp->bitlen = 384;
    zp->funcs = NULL;
    sep_u64 *payload = (sep_u64 *)(void *)(zp + 1);
    for (sep_size_t i = 0; i < P384_LIMBS; ++i) {
        payload[i] = p384_prime[i];
    }
    sep_u64 inverse = 1;
    for (sep_size_t i = 0; i < 6; ++i) {
        inverse *= 2 - payload[0] * inverse;
    }
    payload[P384_LIMBS] = 0 - inverse;
    return zp;
}

static void p384_to_montgomery(sep_u64 *result, const sep_u64 *value) {
    sep_u64 storage[SEP_CCZP_STORAGE_WORDS(P384_LIMBS)];
    sep_cczp_t *zp = make_p384_context(storage);
    sep_u64 shifted[2 * P384_LIMBS];
    for (sep_size_t i = 0; i < P384_LIMBS; ++i) {
        shifted[i] = 0;
        shifted[P384_LIMBS + i] = value[i];
    }
    sep_cczp_modn_ws(NULL, zp, result, 2 * P384_LIMBS, shifted);
}

void sep_ccn_mulmod_p384(
    sep_u64 *result,
    const sep_u64 *a,
    const sep_u64 *b
) {
    sep_u64 storage[SEP_CCZP_STORAGE_WORDS(P384_LIMBS)];
    sep_cczp_t *zp = make_p384_context(storage);
    sep_u64 product[2 * P384_LIMBS];
    sep_ccn_mul(P384_LIMBS, product, a, b);
    sep_cczp_mm_redc_ws(NULL, zp, result, product);
}

void sep_ccn_p384_mul_asm_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *left,
    const sep_u64 *right
) {
    (void)workspace;
    (void)zp;
    sep_ccn_mulmod_p384(result, left, right);
}

void sep_ccn_p384_sqr_asm_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    (void)workspace;
    (void)zp;
    sep_ccn_mulmod_p384(result, value, value);
}

void sep_ccn_p384_from_asm_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    (void)workspace;
    (void)zp;
    const sep_u64 one[P384_LIMBS] = { 1, 0, 0, 0, 0, 0 };
    sep_ccn_mulmod_p384(result, value, one);
}

void sep_ccn_p384_to_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    (void)workspace;
    (void)zp;
    p384_to_montgomery(result, value);
}

int sep_ccn_p384_inv_asm_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    (void)workspace;
    (void)zp;
    sep_u64 exponent[P384_LIMBS];
    for (sep_size_t i = 0; i < P384_LIMBS; ++i) {
        exponent[i] = p384_prime[i];
    }
    (void)sep_ccn_sub1(P384_LIMBS, exponent, exponent, 2);

    sep_u64 accumulator[P384_LIMBS];
    sep_u64 factor[P384_LIMBS];
    sep_u64 check[P384_LIMBS];
    const sep_u64 one[P384_LIMBS] = { 1, 0, 0, 0, 0, 0 };
    p384_to_montgomery(accumulator, one);
    for (sep_size_t i = 0; i < P384_LIMBS; ++i) {
        factor[i] = value[i];
    }
    for (sep_size_t bit = 0; bit < 384; ++bit) {
        if (((exponent[bit >> 6] >> (bit & 63)) & 1) != 0) {
            sep_ccn_mulmod_p384(accumulator, accumulator, factor);
        }
        if (bit + 1 < 384) {
            sep_ccn_mulmod_p384(factor, factor, factor);
        }
    }
    sep_ccn_mulmod_p384(check, accumulator, value);
    sep_u64 one_montgomery[P384_LIMBS];
    p384_to_montgomery(one_montgomery, one);
    if (sep_ccn_cmp_internal(P384_LIMBS, check, one_montgomery) != 0) {
        return P384_INVERSE_FAILURE;
    }
    for (sep_size_t i = 0; i < P384_LIMBS; ++i) {
        result[i] = accumulator[i];
    }
    return 0;
}
