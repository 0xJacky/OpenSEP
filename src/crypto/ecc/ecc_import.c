#include "ecc_internal.h"

#define CCEC_POINT_CANNOT_BE_UNIT (-160)
#define CCEC_COMPRESSED_ENCODING_ERROR (-161)
#define CCEC_UNCOMPRESSED_ENCODING_ERROR (-170)
#define CCEC_HYBRID_ENCODING_ERROR (-171)
#define CCEC_COMPACT_ENCODING_ERROR (-172)

static int read_coordinate(sep_u64 *result, const sep_u8 *input) {
    return sep_ccn_read_uint_public_value(
        ECC_P384_LIMBS,
        result,
        48,
        input
    );
}

int sep_ccec_validate_scalar(
    const sep_ccec_cp_t *curve,
    const sep_u64 *scalar
) {
    const sep_u64 *order = sep_cczp_prime(open_secure_rom_ecc_zq(curve));
    return sep_ccn_cmp_internal(curve->n, scalar, order) < 0 &&
                   sep_ccn_n(curve->n, scalar) != 0
        ? 0
        : -1;
}

int sep_ccec_validate_point_and_projectify_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *curve,
    sep_ccec_projective_point_t *result,
    const sep_ccec_affine_point_t *public_point,
    sep_ccrng_state_t *masking_rng
) {
    const sep_u64 *prime = sep_cczp_prime(curve);
    if (sep_ccn_cmp_internal(curve->n,
                            open_secure_rom_ecc_const_affine_x(public_point),
                            prime) >= 0 ||
        sep_ccn_cmp_internal(curve->n,
                            open_secure_rom_ecc_const_affine_y(public_point),
                            prime) >= 0) {
        return -1;
    }
    const int status = sep_ccec_projectify_ws(
        workspace,
        curve,
        result,
        public_point,
        masking_rng
    );
    if (status != 0) {
        return status;
    }
    return sep_ccec_is_point_ws(workspace, curve, result)
        ? 0
        : ECC_PARAMETER_ERROR;
}

int sep_ccec_import_affine_point_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *curve,
    int format,
    sep_size_t input_length,
    const sep_u8 *input,
    sep_ccec_affine_point_t *point
) {
    if (input_length == 0) {
        return ECC_PARAMETER_ERROR;
    }
    if (input_length == 1 && input[0] == 0) {
        return CCEC_POINT_CANNOT_BE_UNIT;
    }

    int encoding_error;
    const sep_u8 *x_bytes;
    if (format == 4) {
        encoding_error = CCEC_COMPACT_ENCODING_ERROR;
        if (input_length != 48) {
            return encoding_error;
        }
        x_bytes = input;
    } else if (format == 3) {
        encoding_error = CCEC_COMPRESSED_ENCODING_ERROR;
        if (input_length != 49 || (input[0] != 2 && input[0] != 3)) {
            return encoding_error;
        }
        x_bytes = input + 1;
    } else if (format == 1) {
        encoding_error = CCEC_UNCOMPRESSED_ENCODING_ERROR;
        if (input_length != 97 || input[0] != 4) {
            return encoding_error;
        }
        x_bytes = input + 1;
    } else if (format == 2) {
        encoding_error = CCEC_HYBRID_ENCODING_ERROR;
        if (input_length != 97 || (input[0] != 6 && input[0] != 7)) {
            return encoding_error;
        }
        x_bytes = input + 1;
    } else {
        return ECC_PARAMETER_ERROR;
    }

    int status = read_coordinate(open_secure_rom_ecc_affine_x(point), x_bytes);
    if (status != 0 ||
        sep_ccn_cmp_internal(curve->n,
                            open_secure_rom_ecc_affine_x(point),
                            sep_cczp_prime(curve)) >= 0) {
        return encoding_error;
    }
    if (format == 3 || format == 4) {
        status = sep_ccec_affine_point_from_x_ws(
            workspace,
            curve,
            point,
            open_secure_rom_ecc_affine_x(point)
        );
        if (status != 0) {
            return status;
        }
        sep_u64 negated[ECC_P384_LIMBS];
        open_secure_rom_fe_neg(
            negated,
            open_secure_rom_ecc_affine_y(point)
        );
        if ((format == 3 &&
             ((open_secure_rom_ecc_affine_y(point)[0] ^ input[0]) & 1) != 0) ||
            (format == 4 &&
             sep_ccn_cmp_internal(curve->n, negated,
                                  open_secure_rom_ecc_affine_y(point)) < 0)) {
            open_secure_rom_fe_copy(
                open_secure_rom_ecc_affine_y(point),
                negated
            );
        }
    } else {
        status = read_coordinate(
            open_secure_rom_ecc_affine_y(point),
            input + 49
        );
        if (status != 0 ||
            sep_ccn_cmp_internal(curve->n,
                                open_secure_rom_ecc_affine_y(point),
                                sep_cczp_prime(curve)) >= 0) {
            return encoding_error;
        }
        if (format == 2 &&
            ((open_secure_rom_ecc_affine_y(point)[0] ^ input[0]) & 1) != 0) {
            return encoding_error;
        }
    }
    return 0;
}

int sep_ccec_x963_import_pub_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_size_t input_length,
    const sep_u8 *input,
    sep_ccec_pub_ctx_t *key
) {
    if (input_length == 0) {
        return ECC_PARAMETER_ERROR;
    }
    int format;
    if (input[0] == 2 || input[0] == 3) {
        format = 3;
    } else if (input[0] == 4) {
        format = 1;
    } else if (input[0] == 6 || input[0] == 7) {
        format = 2;
    } else if (input[0] == 0 && input_length == 1) {
        return CCEC_POINT_CANNOT_BE_UNIT;
    } else {
        return ECC_PARAMETER_ERROR;
    }
    key->cp = cp;
    sep_ccec_affine_point_t *affine =
        (sep_ccec_affine_point_t *)(void *)key->words;
    int status = sep_ccec_import_affine_point_ws(
        workspace,
        cp,
        format,
        input_length,
        input,
        affine
    );
    if (status != 0) {
        return status;
    }
    open_secure_rom_fe_zero(open_secure_rom_ecc_ctx_z(key));
    open_secure_rom_ecc_ctx_z(key)[0] = 1;
    sep_u64 projective_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    return sep_ccec_validate_point_and_projectify_ws(
        workspace,
        cp,
        (sep_ccec_projective_point_t *)(void *)projective_words,
        affine,
        NULL
    );
}

int sep_ccec_x963_import_pub(
    const sep_ccec_cp_t *cp,
    sep_size_t input_length,
    const sep_u8 *input,
    sep_ccec_pub_ctx_t *key
) {
    return sep_ccec_x963_import_pub_ws(NULL, cp, input_length, input, key);
}

int sep_ccec_import_pub(
    const sep_ccec_cp_t *cp,
    sep_size_t input_length,
    const sep_u8 *input,
    sep_ccec_pub_ctx_t *key
) {
    return sep_ccec_x963_import_pub(cp, input_length, input, key);
}
