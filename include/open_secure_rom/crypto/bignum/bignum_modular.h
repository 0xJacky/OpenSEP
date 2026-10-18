#ifndef OPEN_SECURE_ROM_BIGNUM_MODULAR_H
#define OPEN_SECURE_ROM_BIGNUM_MODULAR_H

#include "open_secure_rom/bignum.h"

typedef struct sep_cczp_funcs {
    void (*add)(
        sep_cc_ws_t *,
        const sep_cczp_t *,
        sep_u64 *,
        const sep_u64 *,
        const sep_u64 *
    );
    void (*sub)(
        sep_cc_ws_t *,
        const sep_cczp_t *,
        sep_u64 *,
        const sep_u64 *,
        const sep_u64 *
    );
    void (*mul)(
        sep_cc_ws_t *,
        const sep_cczp_t *,
        sep_u64 *,
        const sep_u64 *,
        const sep_u64 *
    );
    void (*sqr)(sep_cc_ws_t *, const sep_cczp_t *, sep_u64 *, const sep_u64 *);
    void (*mod)(sep_cc_ws_t *, const sep_cczp_t *, sep_u64 *, const sep_u64 *);
    int (*inv)(sep_cc_ws_t *, const sep_cczp_t *, sep_u64 *, const sep_u64 *);
    int (*sqrt)(sep_cc_ws_t *, const sep_cczp_t *, sep_u64 *, const sep_u64 *);
    void (*to)(sep_cc_ws_t *, const sep_cczp_t *, sep_u64 *, const sep_u64 *);
    void (*from)(sep_cc_ws_t *, const sep_cczp_t *, sep_u64 *, const sep_u64 *);
} sep_cczp_funcs_t;

/* Header, prime, p0 inverse, and R squared. */
#define SEP_CCZP_STORAGE_WORDS(limb_count) (4u + 2u * (limb_count))

const sep_u64 *sep_cczp_prime(const sep_cczp_t *zp);

void sep_ccn_divmod_ws(
    sep_cc_ws_t *workspace,
    sep_size_t dividend_limb_count,
    const sep_u64 *dividend,
    sep_size_t quotient_limb_count,
    sep_u64 *quotient,
    sep_size_t divisor_limb_count,
    sep_u64 *remainder,
    const sep_u64 *divisor
);

int sep_cczp_init_ws(sep_cc_ws_t *workspace, sep_cczp_t *zp);
int sep_cczp_mm_init_ws(
    sep_cc_ws_t *workspace,
    sep_cczp_t *zp,
    sep_size_t limb_count,
    const sep_u64 *prime
);

void sep_cczp_to_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_to_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_from_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_from_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_negate(const sep_cczp_t *, sep_u64 *, const sep_u64 *);
void sep_cczp_cond_negate(
    const sep_cczp_t *,
    sep_u64,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_add_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_cczp_add_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_cczp_sub_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_cczp_sub_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_cczp_div2_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_modn_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    sep_size_t,
    const sep_u64 *
);
void sep_cczp_mod_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_mod_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_mul_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_cczp_mul_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_cczp_sqr_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_sqr_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);

void sep_cczp_mm_redc_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    sep_u64 *
);
void sep_cczp_mm_to_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_mm_from_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_mm_mul_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_cczp_mm_sqr_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_mm_mod_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);

int sep_cczp_power_fast_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
int sep_cczp_inv_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_cczp_inv_update_redc_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    sep_u64,
    const sep_u64 *,
    sep_u64
);
int sep_cczp_inv_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
int sep_cczp_inv_field_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
int sep_cczp_is_quadratic_residue_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    const sep_u64 *
);
int sep_cczp_sqrt_tonelli_shanks_precomp_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    sep_size_t,
    const sep_u64 *,
    const sep_u64 *
);
int sep_cczp_sqrt_default_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
int sep_cczp_sqrt_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);

void sep_ccn_mulmod_p384(sep_u64 *result, const sep_u64 *a, const sep_u64 *b);
void sep_ccn_p384_mul_asm_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *,
    const sep_u64 *
);
void sep_ccn_p384_sqr_asm_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
int sep_ccn_p384_inv_asm_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_ccn_p384_from_asm_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);
void sep_ccn_p384_to_ws(
    sep_cc_ws_t *,
    const sep_cczp_t *,
    sep_u64 *,
    const sep_u64 *
);

#endif
