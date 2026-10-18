#ifndef OPEN_SECURE_ROM_ECC_INTERNAL_H
#define OPEN_SECURE_ROM_ECC_INTERNAL_H

#include "open_secure_rom/ecc.h"

#define ECC_P384_LIMBS 6u
#define ECC_OK 0
#define ECC_PARAMETER_ERROR (-7)

const sep_u64 *open_secure_rom_ecc_b(const sep_ccec_cp_t *cp);
const sep_u64 *open_secure_rom_ecc_gx(const sep_ccec_cp_t *cp);
const sep_u64 *open_secure_rom_ecc_gy(const sep_ccec_cp_t *cp);
const sep_cczp_t *open_secure_rom_ecc_zq(const sep_ccec_cp_t *cp);

sep_u64 *open_secure_rom_ecc_x(sep_ccec_projective_point_t *point);
sep_u64 *open_secure_rom_ecc_y(sep_ccec_projective_point_t *point);
sep_u64 *open_secure_rom_ecc_z(sep_ccec_projective_point_t *point);
const sep_u64 *open_secure_rom_ecc_const_x(
    const sep_ccec_projective_point_t *point
);
const sep_u64 *open_secure_rom_ecc_const_y(
    const sep_ccec_projective_point_t *point
);
const sep_u64 *open_secure_rom_ecc_const_z(
    const sep_ccec_projective_point_t *point
);

sep_u64 *open_secure_rom_ecc_affine_x(sep_ccec_affine_point_t *point);
sep_u64 *open_secure_rom_ecc_affine_y(sep_ccec_affine_point_t *point);
const sep_u64 *open_secure_rom_ecc_const_affine_x(
    const sep_ccec_affine_point_t *point
);
const sep_u64 *open_secure_rom_ecc_const_affine_y(
    const sep_ccec_affine_point_t *point
);

sep_u64 *open_secure_rom_ecc_ctx_x(sep_ccec_pub_ctx_t *key);
sep_u64 *open_secure_rom_ecc_ctx_y(sep_ccec_pub_ctx_t *key);
sep_u64 *open_secure_rom_ecc_ctx_z(sep_ccec_pub_ctx_t *key);
sep_u64 *open_secure_rom_ecc_ctx_k(sep_ccec_full_ctx_t *key);

void open_secure_rom_fe_copy(sep_u64 *result, const sep_u64 *value);
void open_secure_rom_fe_zero(sep_u64 *result);
int open_secure_rom_fe_is_zero(const sep_u64 *value);
int open_secure_rom_fe_equal(const sep_u64 *left, const sep_u64 *right);
void open_secure_rom_fe_add(sep_u64 *result, const sep_u64 *left, const sep_u64 *right);
void open_secure_rom_fe_sub(sep_u64 *result, const sep_u64 *left, const sep_u64 *right);
void open_secure_rom_fe_neg(sep_u64 *result, const sep_u64 *value);
void open_secure_rom_fe_mul(sep_u64 *result, const sep_u64 *left, const sep_u64 *right);
void open_secure_rom_fe_sqr(sep_u64 *result, const sep_u64 *value);
void open_secure_rom_fe_inv(sep_u64 *result, const sep_u64 *value);
int open_secure_rom_fe_sqrt(sep_u64 *result, const sep_u64 *value);

void open_secure_rom_ecc_set_infinity(sep_ccec_projective_point_t *point);
void open_secure_rom_ecc_copy_point(sep_ccec_projective_point_t *result, const sep_ccec_projective_point_t *point);

#endif
