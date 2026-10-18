#ifndef OPEN_SECURE_ROM_ECC_H
#define OPEN_SECURE_ROM_ECC_H

#include "open_secure_rom/bignum_modular.h"

typedef sep_cczp_t sep_ccec_cp_t;

typedef struct sep_ccrng_state sep_ccrng_state_t;
typedef struct sep_ccec_full_ctx sep_ccec_full_ctx_t;
typedef struct sep_ccec_pub_ctx sep_ccec_pub_ctx_t;
typedef struct sep_ccec_affine_point sep_ccec_affine_point_t;
typedef struct sep_ccec_projective_point sep_ccec_projective_point_t;

typedef int (*sep_ccrng_generate_fn)(
    sep_ccrng_state_t *rng,
    sep_size_t output_length,
    void *output
);

struct sep_ccrng_state {
    sep_ccrng_generate_fn generate;
};

struct sep_ccec_affine_point {
    sep_u64 xyz[1];
};

struct sep_ccec_projective_point {
    sep_u64 xyz[1];
};

struct sep_ccec_pub_ctx {
    const sep_ccec_cp_t *cp;
    _Alignas(16) sep_u64 words[];
};

struct sep_ccec_full_ctx {
    const sep_ccec_cp_t *cp;
    _Alignas(16) sep_u64 words[];
};

#define SEP_CCEC_POINT_WORDS(limb_count) (3u * (limb_count))
#define SEP_CCEC_AFFINE_WORDS(limb_count) (2u * (limb_count))
#define SEP_CCEC_PUB_CTX_BYTES(limb_count) (16u + 24u * (limb_count))
#define SEP_CCEC_FULL_CTX_BYTES(limb_count) (16u + 32u * (limb_count))

const sep_ccec_cp_t *sep_ccec_cp_384_asm(void);
const sep_ccec_cp_t *sep_ccec_cp_384(void);
sep_size_t sep_ccec_compressed_x962_export_pub_size(const sep_ccec_cp_t *cp);

int sep_ccec_affinify_jacobian_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_affine_point_t *,
    const sep_ccec_projective_point_t *
);
int sep_ccec_affinify_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_affine_point_t *,
    const sep_ccec_projective_point_t *
);
int sep_ccec_affinify_x_only_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_u64 *,
    const sep_ccec_projective_point_t *
);
int sep_ccec_projectify_jacobian_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_affine_point_t *,
    sep_ccrng_state_t *
);
int sep_ccec_projectify_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_affine_point_t *,
    sep_ccrng_state_t *
);
void sep_ccec_double_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *
);
void sep_ccec_add_normalized_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *,
    sep_bool
);
void sep_ccec_full_add_normalized_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *
);
void sep_ccec_full_add_default_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *
);
void sep_ccec_full_add_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *,
    const sep_ccec_projective_point_t *
);
void sep_ccec_map_to_homogeneous_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    const sep_ccec_projective_point_t *,
    sep_u64 *,
    sep_u64 *
);
sep_bool sep_ccec_is_point_projective_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    const sep_ccec_projective_point_t *
);
sep_bool sep_ccec_is_point_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    const sep_ccec_projective_point_t *
);
sep_bool sep_ccec_is_point_at_infinity(
    const sep_ccec_cp_t *,
    const sep_ccec_projective_point_t *
);
int sep_ccec_affine_point_from_x_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_affine_point_t *,
    const sep_u64 *
);

int sep_ccec_mult_inner_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_u64 *,
    sep_size_t,
    const sep_ccec_projective_point_t *
);
int sep_ccec_mult_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_u64 *,
    sep_size_t,
    const sep_ccec_projective_point_t *
);
int sep_ccec_mult_blinded_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_u64 *,
    const sep_ccec_projective_point_t *,
    sep_ccrng_state_t *
);
void sep_ccec_mult_XYCZaddC_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_u64 *,
    sep_u64 *
);
void sep_ccec_mult_XYCZadd_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_u64 *,
    sep_u64 *
);

int sep_ccec_import_affine_point_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    int,
    sep_size_t,
    const sep_u8 *,
    sep_ccec_affine_point_t *
);
int sep_ccec_validate_point_and_projectify_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_ccec_affine_point_t *,
    sep_ccrng_state_t *
);
int sep_ccec_x963_import_pub_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_size_t,
    const sep_u8 *,
    sep_ccec_pub_ctx_t *
);
int sep_ccec_x963_import_pub(
    const sep_ccec_cp_t *,
    sep_size_t,
    const sep_u8 *,
    sep_ccec_pub_ctx_t *
);
int sep_ccec_import_pub(
    const sep_ccec_cp_t *,
    sep_size_t,
    const sep_u8 *,
    sep_ccec_pub_ctx_t *
);
int sep_ccec_validate_scalar(const sep_ccec_cp_t *, const sep_u64 *);
int sep_ccec_make_pub_from_priv_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccrng_state_t *,
    const sep_u64 *,
    const sep_ccec_affine_point_t *,
    sep_ccec_pub_ctx_t *
);
int sep_ccec_generate_scalar_fips_retry_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccrng_state_t *,
    sep_u64 *
);
int sep_ccec_generate_key_internal_fips_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccrng_state_t *,
    sep_ccec_full_ctx_t *
);

int sep_ccecdh_fast_scalar_mult_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccec_projective_point_t *,
    const sep_u64 *,
    const sep_ccec_affine_point_t *
);
int sep_ccecdh_compute_shared_secret_ws(
    sep_cc_ws_t *,
    sep_ccec_full_ctx_t *,
    sep_ccec_pub_ctx_t *,
    sep_size_t *,
    sep_u8 *,
    sep_ccrng_state_t *
);
int sep_ccecdh_compute_shared_secret(
    sep_ccec_full_ctx_t *,
    sep_ccec_pub_ctx_t *,
    sep_size_t *,
    sep_u8 *,
    sep_ccrng_state_t *
);
int sep_ccecdh_pairwise_consistency_check_ws(
    sep_cc_ws_t *,
    sep_ccec_full_ctx_t *,
    const sep_ccec_affine_point_t *,
    sep_ccrng_state_t *
);
int sep_ccecdh_generate_key_ws(
    sep_cc_ws_t *,
    const sep_ccec_cp_t *,
    sep_ccrng_state_t *,
    sep_ccec_full_ctx_t *
);
int sep_ccecdh_generate_key(
    const sep_ccec_cp_t *,
    sep_ccrng_state_t *,
    sep_ccec_full_ctx_t *
);

#endif
