#include "ecc_internal.h"
#include "open_secure_rom/runtime.h"

static sep_ccec_projective_point_t *point_from_words(sep_u64 *words) {
    return (sep_ccec_projective_point_t *)(void *)words;
}

void open_secure_rom_ecc_copy_point(
    sep_ccec_projective_point_t *result,
    const sep_ccec_projective_point_t *point
) {
    for (sep_size_t i = 0; i < SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS); ++i) {
        result->xyz[i] = point->xyz[i];
    }
}

void open_secure_rom_ecc_set_infinity(sep_ccec_projective_point_t *point) {
    open_secure_rom_fe_zero(open_secure_rom_ecc_x(point));
    open_secure_rom_fe_zero(open_secure_rom_ecc_y(point));
    open_secure_rom_fe_zero(open_secure_rom_ecc_z(point));
    open_secure_rom_ecc_x(point)[0] = 1;
    open_secure_rom_ecc_y(point)[0] = 1;
}

sep_bool sep_ccec_is_point_at_infinity(
    const sep_ccec_cp_t *cp,
    const sep_ccec_projective_point_t *point
) {
    (void)cp;
    return open_secure_rom_fe_is_zero(open_secure_rom_ecc_const_z(point));
}

int sep_ccec_projectify_jacobian_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_ccec_affine_point_t *point,
    sep_ccrng_state_t *rng
) {
    (void)workspace;
    (void)cp;
    (void)rng;
    open_secure_rom_fe_copy(
        open_secure_rom_ecc_x(result),
        open_secure_rom_ecc_const_affine_x(point)
    );
    open_secure_rom_fe_copy(
        open_secure_rom_ecc_y(result),
        open_secure_rom_ecc_const_affine_y(point)
    );
    open_secure_rom_fe_zero(open_secure_rom_ecc_z(result));
    open_secure_rom_ecc_z(result)[0] = 1;
    return 0;
}

int sep_ccec_projectify_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_ccec_affine_point_t *point,
    sep_ccrng_state_t *rng
) {
    return sep_ccec_projectify_jacobian_ws(workspace, cp, result, point, rng);
}

int sep_ccec_affinify_jacobian_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_affine_point_t *result,
    const sep_ccec_projective_point_t *point
) {
    (void)workspace;
    (void)cp;
    if (sep_ccec_is_point_at_infinity(cp, point)) {
        return ECC_PARAMETER_ERROR;
    }
    sep_u64 inverse[ECC_P384_LIMBS];
    sep_u64 inverse_squared[ECC_P384_LIMBS];
    sep_u64 inverse_cubed[ECC_P384_LIMBS];
    open_secure_rom_fe_inv(inverse, open_secure_rom_ecc_const_z(point));
    open_secure_rom_fe_sqr(inverse_squared, inverse);
    open_secure_rom_fe_mul(inverse_cubed, inverse_squared, inverse);
    open_secure_rom_fe_mul(
        open_secure_rom_ecc_affine_x(result),
        open_secure_rom_ecc_const_x(point),
        inverse_squared
    );
    open_secure_rom_fe_mul(
        open_secure_rom_ecc_affine_y(result),
        open_secure_rom_ecc_const_y(point),
        inverse_cubed
    );
    return 0;
}

int sep_ccec_affinify_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_affine_point_t *result,
    const sep_ccec_projective_point_t *point
) {
    return sep_ccec_affinify_jacobian_ws(workspace, cp, result, point);
}

int sep_ccec_affinify_x_only_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_u64 *x,
    const sep_ccec_projective_point_t *point
) {
    sep_u64 affine_words[SEP_CCEC_AFFINE_WORDS(ECC_P384_LIMBS)];
    sep_ccec_affine_point_t *affine =
        (sep_ccec_affine_point_t *)(void *)affine_words;
    const int status = sep_ccec_affinify_ws(workspace, cp, affine, point);
    if (status == 0) {
        open_secure_rom_fe_copy(x, open_secure_rom_ecc_affine_x(affine));
    }
    return status;
}

void sep_ccec_double_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_ccec_projective_point_t *point
) {
    (void)workspace;
    if (sep_ccec_is_point_at_infinity(cp, point) ||
        open_secure_rom_fe_is_zero(open_secure_rom_ecc_const_y(point))) {
        open_secure_rom_ecc_set_infinity(result);
        return;
    }

    sep_u64 delta[ECC_P384_LIMBS];
    sep_u64 gamma[ECC_P384_LIMBS];
    sep_u64 beta[ECC_P384_LIMBS];
    sep_u64 alpha[ECC_P384_LIMBS];
    sep_u64 temporary[ECC_P384_LIMBS];
    sep_u64 x3[ECC_P384_LIMBS];
    sep_u64 y3[ECC_P384_LIMBS];
    sep_u64 z3[ECC_P384_LIMBS];

    open_secure_rom_fe_sqr(delta, open_secure_rom_ecc_const_z(point));
    open_secure_rom_fe_sqr(gamma, open_secure_rom_ecc_const_y(point));
    open_secure_rom_fe_mul(beta, open_secure_rom_ecc_const_x(point), gamma);
    open_secure_rom_fe_sub(alpha, open_secure_rom_ecc_const_x(point), delta);
    open_secure_rom_fe_add(temporary, open_secure_rom_ecc_const_x(point), delta);
    open_secure_rom_fe_mul(alpha, alpha, temporary);
    open_secure_rom_fe_add(temporary, alpha, alpha);
    open_secure_rom_fe_add(alpha, temporary, alpha);

    open_secure_rom_fe_sqr(x3, alpha);
    open_secure_rom_fe_add(temporary, beta, beta);
    open_secure_rom_fe_add(temporary, temporary, temporary);
    open_secure_rom_fe_add(temporary, temporary, temporary);
    open_secure_rom_fe_sub(x3, x3, temporary);

    open_secure_rom_fe_add(z3, open_secure_rom_ecc_const_y(point), open_secure_rom_ecc_const_z(point));
    open_secure_rom_fe_sqr(z3, z3);
    open_secure_rom_fe_sub(z3, z3, gamma);
    open_secure_rom_fe_sub(z3, z3, delta);

    open_secure_rom_fe_add(temporary, beta, beta);
    open_secure_rom_fe_add(temporary, temporary, temporary);
    open_secure_rom_fe_sub(temporary, temporary, x3);
    open_secure_rom_fe_mul(y3, alpha, temporary);
    open_secure_rom_fe_sqr(temporary, gamma);
    open_secure_rom_fe_add(temporary, temporary, temporary);
    open_secure_rom_fe_add(temporary, temporary, temporary);
    open_secure_rom_fe_add(temporary, temporary, temporary);
    open_secure_rom_fe_sub(y3, y3, temporary);

    open_secure_rom_fe_copy(open_secure_rom_ecc_x(result), x3);
    open_secure_rom_fe_copy(open_secure_rom_ecc_y(result), y3);
    open_secure_rom_fe_copy(open_secure_rom_ecc_z(result), z3);
}

void sep_ccec_full_add_default_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_ccec_projective_point_t *s,
    const sep_ccec_projective_point_t *t
) {
    (void)workspace;
    if (sep_ccec_is_point_at_infinity(cp, s)) {
        open_secure_rom_ecc_copy_point(result, t);
        return;
    }
    if (sep_ccec_is_point_at_infinity(cp, t)) {
        open_secure_rom_ecc_copy_point(result, s);
        return;
    }

    sep_u64 z1z1[ECC_P384_LIMBS];
    sep_u64 z2z2[ECC_P384_LIMBS];
    sep_u64 u1[ECC_P384_LIMBS];
    sep_u64 u2[ECC_P384_LIMBS];
    sep_u64 s1[ECC_P384_LIMBS];
    sep_u64 s2[ECC_P384_LIMBS];
    sep_u64 h[ECC_P384_LIMBS];
    sep_u64 i_value[ECC_P384_LIMBS];
    sep_u64 j[ECC_P384_LIMBS];
    sep_u64 r_value[ECC_P384_LIMBS];
    sep_u64 v[ECC_P384_LIMBS];
    sep_u64 temporary[ECC_P384_LIMBS];
    sep_u64 x3[ECC_P384_LIMBS];
    sep_u64 y3[ECC_P384_LIMBS];
    sep_u64 z3[ECC_P384_LIMBS];

    open_secure_rom_fe_sqr(z1z1, open_secure_rom_ecc_const_z(s));
    open_secure_rom_fe_sqr(z2z2, open_secure_rom_ecc_const_z(t));
    open_secure_rom_fe_mul(u1, open_secure_rom_ecc_const_x(s), z2z2);
    open_secure_rom_fe_mul(u2, open_secure_rom_ecc_const_x(t), z1z1);
    open_secure_rom_fe_mul(temporary, open_secure_rom_ecc_const_z(t), z2z2);
    open_secure_rom_fe_mul(s1, open_secure_rom_ecc_const_y(s), temporary);
    open_secure_rom_fe_mul(temporary, open_secure_rom_ecc_const_z(s), z1z1);
    open_secure_rom_fe_mul(s2, open_secure_rom_ecc_const_y(t), temporary);

    if (open_secure_rom_fe_equal(u1, u2)) {
        if (open_secure_rom_fe_equal(s1, s2)) {
            sep_ccec_double_ws(workspace, cp, result, s);
        } else {
            open_secure_rom_ecc_set_infinity(result);
        }
        return;
    }

    open_secure_rom_fe_sub(h, u2, u1);
    open_secure_rom_fe_add(i_value, h, h);
    open_secure_rom_fe_sqr(i_value, i_value);
    open_secure_rom_fe_mul(j, h, i_value);
    open_secure_rom_fe_sub(r_value, s2, s1);
    open_secure_rom_fe_add(r_value, r_value, r_value);
    open_secure_rom_fe_mul(v, u1, i_value);

    open_secure_rom_fe_sqr(x3, r_value);
    open_secure_rom_fe_sub(x3, x3, j);
    open_secure_rom_fe_add(temporary, v, v);
    open_secure_rom_fe_sub(x3, x3, temporary);

    open_secure_rom_fe_sub(temporary, v, x3);
    open_secure_rom_fe_mul(y3, r_value, temporary);
    open_secure_rom_fe_mul(temporary, s1, j);
    open_secure_rom_fe_add(temporary, temporary, temporary);
    open_secure_rom_fe_sub(y3, y3, temporary);

    open_secure_rom_fe_add(z3, open_secure_rom_ecc_const_z(s), open_secure_rom_ecc_const_z(t));
    open_secure_rom_fe_sqr(z3, z3);
    open_secure_rom_fe_sub(z3, z3, z1z1);
    open_secure_rom_fe_sub(z3, z3, z2z2);
    open_secure_rom_fe_mul(z3, z3, h);

    open_secure_rom_fe_copy(open_secure_rom_ecc_x(result), x3);
    open_secure_rom_fe_copy(open_secure_rom_ecc_y(result), y3);
    open_secure_rom_fe_copy(open_secure_rom_ecc_z(result), z3);
}

void sep_ccec_full_add_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_ccec_projective_point_t *s,
    const sep_ccec_projective_point_t *t
) {
    sep_ccec_full_add_default_ws(workspace, cp, result, s, t);
}

void sep_ccec_full_add_normalized_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_ccec_projective_point_t *s,
    const sep_ccec_projective_point_t *t
) {
    sep_ccec_full_add_default_ws(workspace, cp, result, s, t);
}

void sep_ccec_add_normalized_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_ccec_projective_point_t *result,
    const sep_ccec_projective_point_t *s,
    const sep_ccec_projective_point_t *t,
    sep_bool negate_t
) {
    sep_u64 copy_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_ccec_projective_point_t *copy = point_from_words(copy_words);
    open_secure_rom_ecc_copy_point(copy, t);
    if (negate_t != 0) {
        open_secure_rom_fe_neg(
            open_secure_rom_ecc_y(copy),
            open_secure_rom_ecc_y(copy)
        );
    }
    sep_ccec_full_add_default_ws(workspace, cp, result, s, copy);
}

void sep_ccec_map_to_homogeneous_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    const sep_ccec_projective_point_t *point,
    sep_u64 *x,
    sep_u64 *z
) {
    (void)workspace;
    (void)cp;
    open_secure_rom_fe_copy(x, open_secure_rom_ecc_const_x(point));
    open_secure_rom_fe_copy(z, open_secure_rom_ecc_const_z(point));
}

sep_bool sep_ccec_is_point_projective_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    const sep_ccec_projective_point_t *point
) {
    (void)workspace;
    if (sep_ccec_is_point_at_infinity(cp, point)) {
        return 1;
    }
    sep_u64 left[ECC_P384_LIMBS];
    sep_u64 right[ECC_P384_LIMBS];
    sep_u64 z2[ECC_P384_LIMBS];
    sep_u64 z4[ECC_P384_LIMBS];
    sep_u64 z6[ECC_P384_LIMBS];
    sep_u64 temporary[ECC_P384_LIMBS];
    open_secure_rom_fe_sqr(left, open_secure_rom_ecc_const_y(point));
    open_secure_rom_fe_sqr(z2, open_secure_rom_ecc_const_z(point));
    open_secure_rom_fe_sqr(z4, z2);
    open_secure_rom_fe_mul(z6, z4, z2);
    open_secure_rom_fe_sqr(right, open_secure_rom_ecc_const_x(point));
    open_secure_rom_fe_mul(right, right, open_secure_rom_ecc_const_x(point));
    open_secure_rom_fe_mul(temporary, open_secure_rom_ecc_const_x(point), z4);
    open_secure_rom_fe_add(z2, temporary, temporary);
    open_secure_rom_fe_add(temporary, z2, temporary);
    open_secure_rom_fe_sub(right, right, temporary);
    open_secure_rom_fe_mul(temporary, open_secure_rom_ecc_b(cp), z6);
    open_secure_rom_fe_add(right, right, temporary);
    return open_secure_rom_fe_equal(left, right);
}

sep_bool sep_ccec_is_point_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    const sep_ccec_projective_point_t *point
) {
    return sep_ccec_is_point_projective_ws(workspace, cp, point);
}

int sep_ccec_affine_point_from_x_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *curve,
    sep_ccec_affine_point_t *result,
    const sep_u64 *x
) {
    (void)workspace;
    sep_u64 rhs[ECC_P384_LIMBS];
    sep_u64 temporary[ECC_P384_LIMBS];
    open_secure_rom_fe_sqr(rhs, x);
    open_secure_rom_fe_mul(rhs, rhs, x);
    open_secure_rom_fe_add(temporary, x, x);
    open_secure_rom_fe_add(temporary, temporary, x);
    open_secure_rom_fe_sub(rhs, rhs, temporary);
    open_secure_rom_fe_add(rhs, rhs, open_secure_rom_ecc_b(curve));
    const int status = open_secure_rom_fe_sqrt(
        open_secure_rom_ecc_affine_y(result),
        rhs
    );
    if (status == 0) {
        open_secure_rom_fe_copy(open_secure_rom_ecc_affine_x(result), x);
    }
    return status;
}

void sep_ccec_mult_XYCZadd_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_u64 *p,
    sep_u64 *q
) {
    sep_u64 p_point_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_u64 q_point_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_u64 result_words[SEP_CCEC_POINT_WORDS(ECC_P384_LIMBS)];
    sep_ccec_projective_point_t *p_point = point_from_words(p_point_words);
    sep_ccec_projective_point_t *q_point = point_from_words(q_point_words);
    sep_ccec_projective_point_t *result = point_from_words(result_words);
    sep_memzero(p_point_words, sizeof(p_point_words));
    sep_memzero(q_point_words, sizeof(q_point_words));
    open_secure_rom_fe_copy(open_secure_rom_ecc_x(p_point), p);
    open_secure_rom_fe_copy(open_secure_rom_ecc_y(p_point), p + ECC_P384_LIMBS);
    open_secure_rom_fe_copy(open_secure_rom_ecc_x(q_point), q);
    open_secure_rom_fe_copy(open_secure_rom_ecc_y(q_point), q + ECC_P384_LIMBS);
    open_secure_rom_ecc_z(p_point)[0] = 1;
    open_secure_rom_ecc_z(q_point)[0] = 1;
    sep_ccec_full_add_ws(workspace, cp, result, p_point, q_point);
    sep_u64 affine_words[SEP_CCEC_AFFINE_WORDS(ECC_P384_LIMBS)];
    sep_ccec_affine_point_t *affine =
        (sep_ccec_affine_point_t *)(void *)affine_words;
    (void)sep_ccec_affinify_ws(workspace, cp, affine, result);
    open_secure_rom_fe_copy(p, open_secure_rom_ecc_affine_x(affine));
    open_secure_rom_fe_copy(p + ECC_P384_LIMBS, open_secure_rom_ecc_affine_y(affine));
    for (sep_size_t i = 0; i < 2 * ECC_P384_LIMBS; ++i) {
        q[i] = p[i];
    }
}

void sep_ccec_mult_XYCZaddC_ws(
    sep_cc_ws_t *workspace,
    const sep_ccec_cp_t *cp,
    sep_u64 *p,
    sep_u64 *q
) {
    sep_u64 original_p[2 * ECC_P384_LIMBS];
    sep_u64 original_q[2 * ECC_P384_LIMBS];
    for (sep_size_t i = 0; i < 2 * ECC_P384_LIMBS; ++i) {
        original_p[i] = p[i];
        original_q[i] = q[i];
    }
    sep_ccec_mult_XYCZadd_ws(workspace, cp, p, q);
    open_secure_rom_fe_neg(original_q + ECC_P384_LIMBS, original_q + ECC_P384_LIMBS);
    sep_ccec_mult_XYCZadd_ws(workspace, cp, original_p, original_q);
    for (sep_size_t i = 0; i < 2 * ECC_P384_LIMBS; ++i) {
        q[i] = original_p[i];
    }
}
