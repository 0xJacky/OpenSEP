#include "ecc_internal.h"

static sep_u64 p384_curve_storage[8 + 7 * ECC_P384_LIMBS];
static sep_bool p384_curve_initialized;

static const sep_u64 p384_prime[ECC_P384_LIMBS] = {
    UINT64_C(0x00000000ffffffff), UINT64_C(0xffffffff00000000),
    UINT64_C(0xfffffffffffffffe), UINT64_C(0xffffffffffffffff),
    UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff),
};

static const sep_u64 p384_b[ECC_P384_LIMBS] = {
    UINT64_C(0x2a85c8edd3ec2aef), UINT64_C(0xc656398d8a2ed19d),
    UINT64_C(0x0314088f5013875a), UINT64_C(0x181d9c6efe814112),
    UINT64_C(0x988e056be3f82d19), UINT64_C(0xb3312fa7e23ee7e4),
};

static const sep_u64 p384_gx[ECC_P384_LIMBS] = {
    UINT64_C(0x3a545e3872760ab7), UINT64_C(0x5502f25dbf55296c),
    UINT64_C(0x59f741e082542a38), UINT64_C(0x6e1d3b628ba79b98),
    UINT64_C(0x8eb1c71ef320ad74), UINT64_C(0xaa87ca22be8b0537),
};

static const sep_u64 p384_gy[ECC_P384_LIMBS] = {
    UINT64_C(0x7a431d7c90ea0e5f), UINT64_C(0x0a60b1ce1d7e819d),
    UINT64_C(0xe9da3113b5f0b8c0), UINT64_C(0xf8f41dbd289a147c),
    UINT64_C(0x5d9e98bf9292dc29), UINT64_C(0x3617de4a96262c6f),
};

static const sep_u64 p384_order[ECC_P384_LIMBS] = {
    UINT64_C(0xecec196accc52973), UINT64_C(0x581a0db248b0a77a),
    UINT64_C(0xc7634d81f4372ddf), UINT64_C(0xffffffffffffffff),
    UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff),
};

static void copy_words(sep_u64 *result, const sep_u64 *value) {
    for (sep_size_t i = 0; i < ECC_P384_LIMBS; ++i) {
        result[i] = value[i];
    }
}

static sep_ccec_cp_t *initialize_curve(void) {
    sep_ccec_cp_t *cp = (sep_ccec_cp_t *)(void *)p384_curve_storage;
    if (p384_curve_initialized == 0) {
        cp->n = ECC_P384_LIMBS;
        sep_u64 *prime = (sep_u64 *)(void *)(cp + 1);
        copy_words(prime, p384_prime);
        (void)sep_cczp_init_ws(NULL, cp);
        copy_words((sep_u64 *)open_secure_rom_ecc_b(cp), p384_b);
        copy_words((sep_u64 *)open_secure_rom_ecc_gx(cp), p384_gx);
        copy_words((sep_u64 *)open_secure_rom_ecc_gy(cp), p384_gy);
        sep_cczp_t *zq = (sep_cczp_t *)(void *)open_secure_rom_ecc_zq(cp);
        zq->n = ECC_P384_LIMBS;
        copy_words((sep_u64 *)(void *)(zq + 1), p384_order);
        (void)sep_cczp_init_ws(NULL, zq);
        p384_curve_initialized = 1;
    }
    return cp;
}

const sep_ccec_cp_t *sep_ccec_cp_384_asm(void) {
    return initialize_curve();
}

const sep_ccec_cp_t *sep_ccec_cp_384(void) {
    return initialize_curve();
}

sep_size_t sep_ccec_compressed_x962_export_pub_size(const sep_ccec_cp_t *cp) {
    return ((cp->bitlen + 7) >> 3) + 1;
}

const sep_u64 *open_secure_rom_ecc_b(const sep_ccec_cp_t *cp) {
    return sep_cczp_prime(cp) + 1 + 2 * cp->n;
}

const sep_u64 *open_secure_rom_ecc_gx(const sep_ccec_cp_t *cp) {
    return open_secure_rom_ecc_b(cp) + cp->n;
}

const sep_u64 *open_secure_rom_ecc_gy(const sep_ccec_cp_t *cp) {
    return open_secure_rom_ecc_gx(cp) + cp->n;
}

const sep_cczp_t *open_secure_rom_ecc_zq(const sep_ccec_cp_t *cp) {
    return (const sep_cczp_t *)(const void *)(sep_cczp_prime(cp) + 1 + 5 * cp->n);
}

sep_u64 *open_secure_rom_ecc_x(sep_ccec_projective_point_t *point) {
    return point->xyz;
}

sep_u64 *open_secure_rom_ecc_y(sep_ccec_projective_point_t *point) {
    return point->xyz + ECC_P384_LIMBS;
}

sep_u64 *open_secure_rom_ecc_z(sep_ccec_projective_point_t *point) {
    return point->xyz + 2 * ECC_P384_LIMBS;
}

const sep_u64 *open_secure_rom_ecc_const_x(
    const sep_ccec_projective_point_t *point
) {
    return point->xyz;
}

const sep_u64 *open_secure_rom_ecc_const_y(
    const sep_ccec_projective_point_t *point
) {
    return point->xyz + ECC_P384_LIMBS;
}

const sep_u64 *open_secure_rom_ecc_const_z(
    const sep_ccec_projective_point_t *point
) {
    return point->xyz + 2 * ECC_P384_LIMBS;
}

sep_u64 *open_secure_rom_ecc_affine_x(sep_ccec_affine_point_t *point) {
    return point->xyz;
}

sep_u64 *open_secure_rom_ecc_affine_y(sep_ccec_affine_point_t *point) {
    return point->xyz + ECC_P384_LIMBS;
}

const sep_u64 *open_secure_rom_ecc_const_affine_x(
    const sep_ccec_affine_point_t *point
) {
    return point->xyz;
}

const sep_u64 *open_secure_rom_ecc_const_affine_y(
    const sep_ccec_affine_point_t *point
) {
    return point->xyz + ECC_P384_LIMBS;
}

sep_u64 *open_secure_rom_ecc_ctx_x(sep_ccec_pub_ctx_t *key) {
    return key->words;
}

sep_u64 *open_secure_rom_ecc_ctx_y(sep_ccec_pub_ctx_t *key) {
    return key->words + ECC_P384_LIMBS;
}

sep_u64 *open_secure_rom_ecc_ctx_z(sep_ccec_pub_ctx_t *key) {
    return key->words + 2 * ECC_P384_LIMBS;
}

sep_u64 *open_secure_rom_ecc_ctx_k(sep_ccec_full_ctx_t *key) {
    return key->words + 3 * ECC_P384_LIMBS;
}
