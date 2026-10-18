#ifndef OPEN_SECURE_ROM_BIGNUM_H
#define OPEN_SECURE_ROM_BIGNUM_H

#include "open_secure_rom/types.h"

typedef struct sep_ccrng_state sep_ccrng_state_t;

sep_u64 sep_ccn_mul1_asm(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_u64 v);
sep_u64 sep_ccn_mul1_veneer(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_u64 v);
sep_u64 sep_ccn_addmul1_asm(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_u64 v);
sep_u64 sep_ccn_addmul1(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_u64 v);
sep_u64 sep_ccn_add1(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_u64 v);
sep_u64 sep_ccn_add1_ws(sep_cc_ws_t *ws, sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_u64 v);
sep_u64 sep_ccn_sub1(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_u64 v);
sep_u64 sep_ccn_add(sep_size_t n, sep_u64 *r, const sep_u64 *s, const sep_u64 *t);
sep_u64 sep_ccn_add_ws(sep_cc_ws_t *ws, sep_size_t n, sep_u64 *r, const sep_u64 *s, const sep_u64 *t);
sep_u64 sep_ccn_sub(sep_size_t n, sep_u64 *r, const sep_u64 *s, const sep_u64 *t);
sep_u64 sep_ccn_sub_ws(sep_cc_ws_t *ws, sep_size_t n, sep_u64 *r, const sep_u64 *s, const sep_u64 *t);
sep_u64 sep_ccn_subn(sep_size_t rn, sep_u64 *r, const sep_u64 *s, sep_size_t tn, const sep_u64 *t);
void sep_ccn_mul(sep_size_t n, sep_u64 *r, const sep_u64 *s, const sep_u64 *t);
void sep_ccn_sqr_ws(sep_cc_ws_t *ws, sep_size_t n, sep_u64 *r, const sep_u64 *s);
void sep_ccn_zero(sep_size_t n, sep_u64 *r);
void sep_ccn_seti(sep_size_t n, sep_u64 *r, sep_u64 word);
void sep_ccn_neg(sep_size_t n, sep_u64 *r, const sep_u64 *s);
void sep_ccn_cond_neg(sep_size_t n, sep_u64 condition, sep_u64 *r, const sep_u64 *s);
sep_u64 sep_ccn_cond_add(sep_size_t n, sep_u64 condition, sep_u64 *r, const sep_u64 *x, const sep_u64 *y);
sep_u64 sep_ccn_cond_rsub(sep_size_t n, sep_u64 condition, sep_u64 *r, const sep_u64 *left, const sep_u64 *right);
void sep_ccn_cond_clear(sep_size_t n, sep_u64 condition, sep_u64 *value);
void sep_ccn_cond_swap(sep_size_t n, sep_u64 selector, sep_u64 *left, sep_u64 *right);
void sep_ccn_mux(sep_size_t n, sep_u64 selector, sep_u64 *r, const sep_u64 *one, const sep_u64 *zero);
void sep_ccn_mux_seed_mask(sep_u64 seed);
int sep_cc_cmp_safe_internal(sep_size_t length, const void *left, const void *right);
int sep_cc_cmp_safe(sep_size_t length, const void *left, const void *right);
int sep_ccn_cmp_asm(sep_size_t n, const sep_u64 *left, const sep_u64 *right);
int sep_ccn_cmp_public_value(sep_size_t n, const sep_u64 *s, const sep_u64 *t);
int sep_ccn_cmp_internal(sep_size_t n, const sep_u64 *s, const sep_u64 *t);
int sep_ccn_cmpn_public_value(sep_size_t sn, const sep_u64 *s, sep_size_t tn, const sep_u64 *t);
int sep_ccn_cmpn_internal(sep_size_t sn, const sep_u64 *s, sep_size_t tn, const sep_u64 *t);
sep_size_t sep_ccn_n_asm(sep_size_t n, const sep_u64 *limbs);
sep_size_t sep_ccn_n(sep_size_t n, const sep_u64 *limbs);
sep_size_t sep_ccn_bitlen_internal(sep_size_t n, const sep_u64 *limbs);
sep_size_t sep_ccn_bitlen(sep_size_t n, const sep_u64 *limbs);
sep_size_t sep_bignum_bit_length(sep_size_t n, const sep_u64 *limbs);
sep_size_t sep_cczp_n(const sep_cczp_t *zp);
sep_size_t sep_cczp_bitlen(const sep_cczp_t *zp);
void sep_ccn_set_bit(sep_u64 *limbs, sep_size_t bit_index, sep_u64 value);
void sep_ccn_shift_right_asm(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_size_t shift);
sep_u64 sep_ccn_shift_right(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_size_t shift);
void sep_ccn_shift_right_multi(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_size_t shift);
void sep_ccn_shift_left(sep_size_t n, sep_u64 *r, const sep_u64 *s, sep_size_t shift);
int sep_ccn_read_uint_public_value(sep_size_t n, sep_u64 *r, sep_size_t length, const sep_u8 *input);
int sep_ccn_read_uint(sep_size_t n, sep_u64 *r, sep_size_t length, const sep_u8 *input);
sep_size_t sep_ccn_write_uint_size(sep_size_t n, const sep_u64 *limbs);
void sep_ccn_write_uint_public_value(sep_size_t n, const sep_u64 *limbs, sep_size_t length, void *output);
void sep_ccn_write_uint_internal(sep_size_t n, const sep_u64 *limbs, sep_size_t length, void *output);
int sep_ccn_write_uint_padded_ct_internal(sep_size_t n, const sep_u64 *limbs, sep_size_t length, sep_u8 *output);
int sep_ccn_write_uint_padded_ct(sep_size_t n, const sep_u64 *limbs, sep_size_t length, sep_u8 *output);
sep_size_t sep_ccn_write_uint_padded_internal(sep_size_t n, const sep_u64 *limbs, sep_size_t length, sep_u8 *output);
sep_size_t sep_ccn_write_uint_padded(sep_size_t n, const sep_u64 *limbs, sep_size_t length, sep_u8 *output);
void sep_ccn_swap(sep_size_t n, sep_u64 *limbs);
void sep_ccn_gcd_approximate(
    sep_size_t limb_count,
    const sep_u64 *u,
    sep_u64 *u_approximation,
    const sep_u64 *v,
    sep_u64 *v_approximation
);
sep_u64 sep_ccn_gcd_update_ws(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *u,
    sep_u64 f,
    const sep_u64 *v,
    sep_u64 g
);
int sep_ccn_random_bits(
    sep_size_t bit_count,
    sep_u64 *result,
    sep_ccrng_state_t *rng
);
int sep_ccn_random_bits_fips(
    sep_size_t bit_count,
    sep_u64 *result,
    sep_ccrng_state_t *rng
);

#endif
