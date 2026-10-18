#include "ecc_internal.h"

static sep_ccec_projective_point_t *point_from_words(sep_u64 *words) {
    return (sep_ccec_projective_point_t *)(void *)words;
}

int sep_ccec_mult_inner_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_u64 *scalar,
    sep_size_t scalar_bit_length,
    const sep_ccec_projective_point_t *point
) {
    const sep_cczp_t *zq = open_secure_rom_ecc_zq(cp);
    if (scalar_bit_length > zq->bitlen) {
        return ECC_PARAMETER_ERROR;
    }
    sep_u64 accumulator_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_u64 temporary_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_ccec_projective_point_t *accumulator =
        point_from_words(accumulator_words);
    sep_ccec_projective_point_t *temporary = point_from_words(temporary_words);
    open_secure_rom_ecc_set_infinity(accumulator);
    for (sep_size_t bit = scalar_bit_length; bit != 0; --bit) {
        sep_ccec_double_ws(workspace, cp, temporary, accumulator);
        open_secure_rom_ecc_copy_point(accumulator, temporary);
        const sep_size_t index = bit - 1;
        if (((scalar[index >> 6] >> (index & 63)) & 1) != 0) {
            sep_ccec_full_add_ws(workspace, cp, temporary, accumulator, point);
            open_secure_rom_ecc_copy_point(accumulator, temporary);
        }
    }
    open_secure_rom_ecc_copy_point(result, accumulator);
    return 0;
}

int sep_ccec_mult_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_u64 *scalar,
    sep_size_t scalar_bit_length,
    const sep_ccec_projective_point_t *point
) {
    return sep_ccec_mult_inner_ws(
        workspace,
        cp,
        result,
        scalar,
        scalar_bit_length,
        point
    );
}

int sep_ccec_mult_blinded_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_u64 *scalar,
    const sep_ccec_projective_point_t *point,
    sep_ccrng_state_t *rng
) {
    (void)rng;
    const sep_size_t bit_length = sep_ccn_bitlen(cp->n, scalar);
    if (bit_length > open_secure_rom_ecc_zq(cp)->bitlen) {
        return ECC_PARAMETER_ERROR;
    }
    return sep_ccec_mult_ws(workspace, cp, result, scalar, bit_length, point);
}

int sep_ccecdh_fast_scalar_mult_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_u64 *scalar,
    const sep_ccec_affine_point_t *base
) {
    sep_u64 point_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_ccec_projective_point_t *point = point_from_words(point_words);
    int status = sep_ccec_projectify_ws(workspace, cp, point, base, NULL);
    if (status == 0) {
        status = sep_ccec_mult_ws(
            workspace,
            cp,
            result,
            scalar,
            sep_ccn_bitlen(cp->n, scalar),
            point
        );
    }
    return status;
}
