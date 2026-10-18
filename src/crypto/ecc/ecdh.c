#include "ecc_internal.h"

static sep_ccec_projective_point_t *point_from_words(sep_u64 *words) {
    return (sep_ccec_projective_point_t *)(void *)words;
}

int sep_ccec_make_pub_from_priv_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *curve,
    sep_ccrng_state_t *masking_rng,
    const sep_u64 *scalar,
    const sep_ccec_affine_point_t *generator,
    sep_ccec_pub_ctx_t *key
) {
    if (sep_ccec_validate_scalar(curve, scalar) != 0) {
        return -22;
    }
    const sep_ccec_affine_point_t *base = generator;
    if (base == NULL) {
        base = (const sep_ccec_affine_point_t *)(const void *)
            open_secure_rom_ecc_gx(curve);
    }
    sep_u64 base_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_u64 result_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_ccec_projective_point_t *base_point = point_from_words(base_words);
    sep_ccec_projective_point_t *result = point_from_words(result_words);
    int status = sep_ccec_validate_point_and_projectify_ws(
        workspace,
        curve,
        base_point,
        base,
        masking_rng
    );
    if (status != 0) {
        return status;
    }
    status = sep_ccec_mult_blinded_ws(
        workspace,
        curve,
        result,
        scalar,
        base_point,
        masking_rng
    );
    if (status != 0) {
        return -16;
    }
    if (!sep_ccec_is_point_projective_ws(workspace, curve, result)) {
        return -19;
    }
    key->cp = curve;
    status = sep_ccec_affinify_ws(
        workspace,
        curve,
        (sep_ccec_affine_point_t *)(void *)key->words,
        result
    );
    if (status != 0) {
        return -17;
    }
    open_secure_rom_fe_zero(open_secure_rom_ecc_ctx_z(key));
    open_secure_rom_ecc_ctx_z(key)[0] = 1;
    return 0;
}

int sep_ccec_generate_scalar_fips_retry_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *curve,
    sep_ccrng_state_t *rng,
    sep_u64 *scalar
) {
    (void)workspace;
    for (sep_size_t attempt = 0; attempt < 100; ++attempt) {
        const int status = rng->generate(rng, 48, scalar);
        if (status != 0) {
            return status;
        }
        if (sep_ccec_validate_scalar(curve, scalar) == 0) {
            return 0;
        }
    }
    return -15;
}

int sep_ccec_generate_key_internal_fips_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *curve,
    sep_ccrng_state_t *rng,
    sep_ccec_full_ctx_t *key
) {
    key->cp = curve;
    sep_u64 *scalar = open_secure_rom_ecc_ctx_k(key);
    int status = sep_ccec_generate_scalar_fips_retry_ws(
        workspace,
        curve,
        rng,
        scalar
    );
    if (status == 0) {
        status = sep_ccec_make_pub_from_priv_ws(
            workspace,
            curve,
            rng,
            scalar,
            NULL,
            (sep_ccec_pub_ctx_t *)(void *)key
        );
    }
    return status;
}

int sep_ccecdh_compute_shared_secret_ws(
    sep_cc_ws_t *workspace,
    sep_ccec_full_ctx_t *private_key,
    sep_ccec_pub_ctx_t *public_key,
    sep_size_t *shared_secret_length,
    sep_u8 *shared_secret,
    sep_ccrng_state_t *masking_rng
) {
    const sep_size_t capacity = *shared_secret_length;
    *shared_secret_length = 0;
    const sep_ccec_cp_t *cp = private_key->cp;
    if (capacity < 48 || cp != public_key->cp ||
        sep_ccec_validate_scalar(cp, open_secure_rom_ecc_ctx_k(private_key)) != 0) {
        return -1;
    }

    sep_u64 public_point_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_u64 result_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_ccec_projective_point_t *public_point =
        point_from_words(public_point_words);
    sep_ccec_projective_point_t *result = point_from_words(result_words);
    const sep_ccec_affine_point_t *public_affine =
        (const sep_ccec_affine_point_t *)(const void *)public_key->words;
    if (sep_ccec_validate_point_and_projectify_ws(
            workspace,
            cp,
            public_point,
            public_affine,
            masking_rng
        ) != 0 ||
        sep_ccec_mult_blinded_ws(
            workspace,
            cp,
            result,
            open_secure_rom_ecc_ctx_k(private_key),
            public_point,
            masking_rng
        ) != 0 ||
        !sep_ccec_is_point_projective_ws(workspace, cp, result)) {
        return -1;
    }
    sep_u64 x[ECC_P384_LIMBS];
    if (sep_ccec_affinify_x_only_ws(workspace, cp, x, result) != 0) {
        return -1;
    }
    if (sep_ccn_write_uint_padded_ct(
            ECC_P384_LIMBS,
            x,
            48,
            shared_secret
        ) != 0) {
        return -1;
    }
    *shared_secret_length = 48;
    return 0;
}

int sep_ccecdh_compute_shared_secret(
    sep_ccec_full_ctx_t *private_key,
    sep_ccec_pub_ctx_t *public_key,
    sep_size_t *shared_secret_length,
    sep_u8 *shared_secret,
    sep_ccrng_state_t *masking_rng
) {
    return sep_ccecdh_compute_shared_secret_ws(
        NULL,
        private_key,
        public_key,
        shared_secret_length,
        shared_secret,
        masking_rng
    );
}

int sep_ccecdh_pairwise_consistency_check_ws(
    sep_cc_ws_t *workspace,
    sep_ccec_full_ctx_t *full_key,
    const sep_ccec_affine_point_t *base,
    sep_ccrng_state_t *rng
) {
    sep_u8 generated_storage[SEP_CCEC_PUB_CTX_BYTES(ECC_P384_LIMBS)]
        __attribute__((aligned(16)));
    sep_ccec_pub_ctx_t *generated =
        (sep_ccec_pub_ctx_t *)(void *)generated_storage;
    const int status = sep_ccec_make_pub_from_priv_ws(
        workspace,
        full_key->cp,
        rng,
        open_secure_rom_ecc_ctx_k(full_key),
        base,
        generated
    );
    if (status != 0) {
        return status;
    }
    return open_secure_rom_fe_equal(
               open_secure_rom_ecc_ctx_x(generated),
               full_key->words
           ) &&
           open_secure_rom_fe_equal(
               open_secure_rom_ecc_ctx_y(generated),
               full_key->words + ECC_P384_LIMBS
           )
        ? 0
        : -1;
}

int sep_ccecdh_generate_key_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *curve,
    sep_ccrng_state_t *rng,
    sep_ccec_full_ctx_t *key
) {
    int status = sep_ccec_generate_key_internal_fips_ws(
        workspace,
        curve,
        rng,
        key
    );
    if (status == 0 &&
        sep_ccecdh_pairwise_consistency_check_ws(
            workspace,
            key,
            NULL,
            rng
        ) != 0) {
        status = -18;
    }
    return status;
}

int sep_ccecdh_generate_key(
    const sep_ccec_cp_t *curve,
    sep_ccrng_state_t *rng,
    sep_ccec_full_ctx_t *key
) {
    return sep_ccecdh_generate_key_ws(NULL, curve, rng, key);
}
