#include "open_secure_rom/bignum_modular.h"

#include "open_secure_rom/runtime.h"

#define SEP_CCERR_PARAMETER (-7)
#define SEP_CCERR_INTERNAL (-28)

static const sep_cczp_funcs_t default_funcs;
static const sep_cczp_funcs_t montgomery_funcs;

static sep_u64 *zp_payload(sep_cczp_t *zp) {
    return (sep_u64 *)(void *)(zp + 1);
}

static sep_u64 *zp_p0inv(sep_cczp_t *zp) {
    return zp_payload(zp) + zp->n;
}

static const sep_u64 *zp_r2(const sep_cczp_t *zp) {
    return sep_cczp_prime(zp) + zp->n + 1;
}

static const sep_cczp_funcs_t *zp_funcs(const sep_cczp_t *zp) {
    return (const sep_cczp_funcs_t *)zp->funcs;
}

static void copy_limbs(sep_size_t n, sep_u64 *r, const sep_u64 *x) {
    for (sep_size_t i = 0; i < n; ++i) {
        r[i] = x[i];
    }
}

static int is_zero(sep_size_t n, const sep_u64 *x) {
    sep_u64 aggregate = 0;
    for (sep_size_t i = 0; i < n; ++i) {
        aggregate |= x[i];
    }
    return aggregate == 0;
}

static int is_one(sep_size_t n, const sep_u64 *x) {
    if (n == 0 || x[0] != 1) {
        return 0;
    }
    for (sep_size_t i = 1; i < n; ++i) {
        if (x[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static sep_u64 shift_left_one(sep_size_t n, sep_u64 *x) {
    sep_u64 carry = 0;
    for (sep_size_t i = 0; i < n; ++i) {
        const sep_u64 next = x[i] >> 63;
        x[i] = (x[i] << 1) | carry;
        carry = next;
    }
    return carry;
}

static int compare_limbs(sep_size_t n, const sep_u64 *x, const sep_u64 *y) {
    for (sep_size_t i = n; i != 0; --i) {
        if (x[i - 1] > y[i - 1]) {
            return 1;
        }
        if (x[i - 1] < y[i - 1]) {
            return -1;
        }
    }
    return 0;
}

static sep_u64 subtract_limbs(
    sep_size_t n,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    sep_u64 borrow = 0;
    for (sep_size_t i = 0; i < n; ++i) {
        const sep_u64 source = x[i];
        const unsigned __int128 subtrahend =
            (unsigned __int128)y[i] + borrow;
        result[i] = source - (sep_u64)subtrahend;
        borrow = (unsigned __int128)source < subtrahend;
    }
    return borrow;
}

static int reduce_shift_bit(
    sep_size_t n,
    sep_u64 *remainder,
    const sep_u64 *modulus,
    sep_u64 bit
) {
    (void)shift_left_one(n + 1, remainder);
    remainder[0] |= bit & 1;
    int greater_or_equal = remainder[n] != 0;
    if (!greater_or_equal) {
        greater_or_equal = compare_limbs(n, remainder, modulus) >= 0;
    }
    if (greater_or_equal) {
        const sep_u64 borrow = subtract_limbs(
            n,
            remainder,
            remainder,
            modulus
        );
        remainder[n] -= borrow;
        return 1;
    }
    return 0;
}

static void reduce_limbs(
    sep_size_t n,
    sep_u64 *result,
    sep_size_t input_n,
    const sep_u64 *input,
    const sep_u64 *modulus
) {
    sep_u64 remainder[n + 1];
    sep_ccn_zero(n + 1, remainder);
    for (sep_size_t bit = input_n * 64; bit != 0; --bit) {
        const sep_size_t index = bit - 1;
        (void)reduce_shift_bit(
            n,
            remainder,
            modulus,
            (input[index >> 6] >> (index & 63)) & 1
        );
    }
    copy_limbs(n, result, remainder);
}

static void multiply_mod(
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    const sep_size_t n = zp->n;
    sep_u64 product[2 * n];
    sep_ccn_mul(n, product, x, y);
    reduce_limbs(n, result, 2 * n, product, sep_cczp_prime(zp));
}

static void scalar_mod(
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    sep_u64 scalar
) {
    const sep_size_t n = zp->n;
    sep_u64 accumulator[n];
    sep_u64 addend[n];
    sep_ccn_zero(n, accumulator);
    copy_limbs(n, addend, x);
    while (scalar != 0) {
        if ((scalar & 1) != 0) {
            sep_cczp_add_default_ws(NULL, zp, accumulator, accumulator, addend);
        }
        scalar >>= 1;
        if (scalar != 0) {
            sep_cczp_add_default_ws(NULL, zp, addend, addend, addend);
        }
    }
    copy_limbs(n, result, accumulator);
}

const sep_u64 *sep_cczp_prime(const sep_cczp_t *zp) {
    return (const sep_u64 *)(const void *)(zp + 1);
}

void sep_ccn_divmod_ws(
    sep_cc_ws_t *workspace,
    sep_size_t dividend_limb_count,
    const sep_u64 *dividend,
    sep_size_t quotient_limb_count,
    sep_u64 *quotient,
    sep_size_t divisor_limb_count,
    sep_u64 *remainder,
    const sep_u64 *divisor
) {
    (void)workspace;
    const sep_size_t significant_divisor =
        sep_ccn_n(divisor_limb_count, divisor);
    if (quotient != NULL) {
        sep_ccn_zero(quotient_limb_count, quotient);
    }
    sep_u64 partial[significant_divisor + 1];
    sep_ccn_zero(significant_divisor + 1, partial);
    for (sep_size_t bit = dividend_limb_count * 64; bit != 0; --bit) {
        const sep_size_t index = bit - 1;
        if (reduce_shift_bit(
                significant_divisor,
                partial,
                divisor,
                (dividend[index >> 6] >> (index & 63)) & 1
            )) {
            if (quotient != NULL && (index >> 6) < quotient_limb_count) {
                quotient[index >> 6] |= (sep_u64)1 << (index & 63);
            }
        }
    }
    if (remainder != NULL) {
        copy_limbs(significant_divisor, remainder, partial);
        sep_ccn_zero(
            divisor_limb_count - significant_divisor,
            remainder + significant_divisor
        );
    }
}

void sep_cczp_to_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    (void)workspace;
    copy_limbs(zp->n, result, value);
}

void sep_cczp_to_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    zp_funcs(zp)->to(workspace, zp, result, value);
}

void sep_cczp_from_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    (void)workspace;
    copy_limbs(zp->n, result, value);
}

void sep_cczp_from_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    zp_funcs(zp)->from(workspace, zp, result, value);
}

void sep_cczp_negate(
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    const sep_size_t n = zp->n;
    if (is_zero(n, value)) {
        sep_ccn_zero(n, result);
    } else {
        (void)sep_ccn_sub(n, result, sep_cczp_prime(zp), value);
    }
}

void sep_cczp_cond_negate(
    const sep_cczp_t *zp,
    sep_u64 condition,
    sep_u64 *result,
    const sep_u64 *value
) {
    if ((condition & 1) != 0 && !is_zero(zp->n, value)) {
        (void)sep_ccn_sub(zp->n, result, sep_cczp_prime(zp), value);
    } else {
        copy_limbs(zp->n, result, value);
    }
}

void sep_cczp_add_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    (void)workspace;
    const sep_size_t n = zp->n;
    sep_u64 sum[n + 1];
    sep_u64 carry = 0;
    for (sep_size_t i = 0; i < n; ++i) {
        const unsigned __int128 value =
            (unsigned __int128)x[i] + y[i] + carry;
        sum[i] = (sep_u64)value;
        carry = (sep_u64)(value >> 64);
    }
    sum[n] = carry;
    if (sum[n] != 0 || compare_limbs(n, sum, sep_cczp_prime(zp)) >= 0) {
        const sep_u64 borrow = subtract_limbs(
            n,
            sum,
            sum,
            sep_cczp_prime(zp)
        );
        sum[n] -= borrow;
    }
    copy_limbs(n, result, sum);
}

void sep_cczp_add_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    zp_funcs(zp)->add(workspace, zp, result, x, y);
}

void sep_cczp_sub_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    (void)workspace;
    const sep_size_t n = zp->n;
    const sep_u64 borrow = subtract_limbs(n, result, x, y);
    if (borrow != 0) {
        sep_u64 carry = 0;
        for (sep_size_t i = 0; i < n; ++i) {
            const unsigned __int128 value =
                (unsigned __int128)result[i] + sep_cczp_prime(zp)[i] + carry;
            result[i] = (sep_u64)value;
            carry = (sep_u64)(value >> 64);
        }
    }
}

void sep_cczp_sub_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    zp_funcs(zp)->sub(workspace, zp, result, x, y);
}

void sep_cczp_div2_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    (void)workspace;
    const sep_size_t n = zp->n;
    sep_u64 expanded[n + 1];
    copy_limbs(n, expanded, value);
    expanded[n] = 0;
    if ((value[0] & 1) != 0) {
        sep_u64 carry = 0;
        for (sep_size_t i = 0; i < n; ++i) {
            const unsigned __int128 sum =
                (unsigned __int128)expanded[i] + sep_cczp_prime(zp)[i] + carry;
            expanded[i] = (sep_u64)sum;
            carry = (sep_u64)(sum >> 64);
        }
        expanded[n] = carry;
    }
    sep_u64 carry = 0;
    for (sep_size_t i = n + 1; i != 0; --i) {
        const sep_u64 next = expanded[i - 1] << 63;
        expanded[i - 1] = (expanded[i - 1] >> 1) | carry;
        carry = next;
    }
    copy_limbs(n, result, expanded);
}

void sep_cczp_modn_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    sep_size_t input_limb_count,
    const sep_u64 *input
) {
    (void)workspace;
    reduce_limbs(
        zp->n,
        result,
        input_limb_count,
        input,
        sep_cczp_prime(zp)
    );
}

void sep_cczp_mod_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *double_width_input
) {
    sep_cczp_modn_ws(workspace, zp, result, 2 * zp->n, double_width_input);
}

void sep_cczp_mod_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *double_width_value
) {
    zp_funcs(zp)->mod(workspace, zp, result, double_width_value);
}

void sep_cczp_mul_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    (void)workspace;
    multiply_mod(zp, result, x, y);
}

void sep_cczp_mul_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    zp_funcs(zp)->mul(workspace, zp, result, x, y);
}

void sep_cczp_sqr_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x
) {
    sep_cczp_mul_default_ws(workspace, zp, result, x, x);
}

void sep_cczp_sqr_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x
) {
    zp_funcs(zp)->sqr(workspace, zp, result, x);
}

void sep_cczp_mm_redc_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    sep_u64 *double_width_value
) {
    (void)workspace;
    const sep_size_t n = zp->n;
    const sep_u64 *prime = sep_cczp_prime(zp);
    const sep_u64 p0inv = prime[n];
    sep_u64 temporary[2 * n + 1];
    copy_limbs(2 * n, temporary, double_width_value);
    temporary[2 * n] = 0;

    for (sep_size_t i = 0; i < n; ++i) {
        const sep_u64 multiplier = temporary[i] * p0inv;
        sep_u64 carry = 0;
        for (sep_size_t j = 0; j < n; ++j) {
            const unsigned __int128 value =
                (unsigned __int128)multiplier * prime[j] +
                temporary[i + j] + carry;
            temporary[i + j] = (sep_u64)value;
            carry = (sep_u64)(value >> 64);
        }
        sep_size_t index = i + n;
        while (carry != 0) {
            const unsigned __int128 value =
                (unsigned __int128)temporary[index] + carry;
            temporary[index] = (sep_u64)value;
            carry = (sep_u64)(value >> 64);
            ++index;
        }
    }

    copy_limbs(n, result, temporary + n);
    if (temporary[2 * n] != 0 ||
        compare_limbs(n, result, prime) >= 0) {
        (void)subtract_limbs(n, result, result, prime);
    }
}

void sep_cczp_mm_to_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x
) {
    const sep_size_t n = zp->n;
    sep_u64 product[2 * n];
    sep_ccn_mul(n, product, x, zp_r2(zp));
    sep_cczp_mm_redc_ws(workspace, zp, result, product);
}

void sep_cczp_mm_from_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x
) {
    const sep_size_t n = zp->n;
    sep_u64 expanded[2 * n];
    copy_limbs(n, expanded, x);
    sep_ccn_zero(n, expanded + n);
    sep_cczp_mm_redc_ws(workspace, zp, result, expanded);
}

void sep_cczp_mm_mul_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    const sep_size_t n = zp->n;
    sep_u64 product[2 * n];
    sep_ccn_mul(n, product, x, y);
    sep_cczp_mm_redc_ws(workspace, zp, result, product);
}

void sep_cczp_mm_sqr_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    sep_cczp_mm_mul_ws(workspace, zp, result, value, value);
}

void sep_cczp_mm_mod_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *double_width_input
) {
    const sep_size_t n = zp->n;
    sep_u64 copy[2 * n];
    copy_limbs(2 * n, copy, double_width_input);
    sep_cczp_mm_redc_ws(workspace, zp, result, copy);
}

int sep_cczp_power_fast_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *base,
    const sep_u64 *exponent
) {
    const sep_size_t n = zp->n;
    sep_u64 accumulator[n];
    sep_u64 factor[n];
    sep_ccn_seti(n, accumulator, 1);
    sep_cczp_to_ws(workspace, zp, accumulator, accumulator);
    copy_limbs(n, factor, base);
    const sep_size_t bit_length = sep_ccn_bitlen(n, exponent);
    for (sep_size_t bit = 0; bit < bit_length; ++bit) {
        if (((exponent[bit >> 6] >> (bit & 63)) & 1) != 0) {
            sep_cczp_mul_ws(workspace, zp, accumulator, accumulator, factor);
        }
        if (bit + 1 < bit_length) {
            sep_cczp_sqr_ws(workspace, zp, factor, factor);
        }
    }
    copy_limbs(n, result, accumulator);
    return 0;
}

int sep_cczp_inv_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    const sep_size_t n = zp->n;
    if (sep_ccn_cmp_internal(n, value, sep_cczp_prime(zp)) >= 0 ||
        is_zero(n, value)) {
        sep_ccn_zero(n, result);
        return SEP_CCERR_PARAMETER;
    }
    sep_u64 exponent[n];
    sep_u64 check[n];
    sep_u64 one[n];
    (void)sep_ccn_sub1(n, exponent, sep_cczp_prime(zp), 2);
    (void)sep_cczp_power_fast_ws(workspace, zp, result, value, exponent);
    sep_cczp_mul_ws(workspace, zp, check, result, value);
    sep_ccn_seti(n, one, 1);
    sep_cczp_to_ws(workspace, zp, one, one);
    if (sep_ccn_cmp_internal(n, check, one) != 0) {
        sep_ccn_zero(n, result);
        return SEP_CCERR_PARAMETER;
    }
    return 0;
}

void sep_cczp_inv_update_redc_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *a,
    sep_u64 f,
    const sep_u64 *b,
    sep_u64 g
) {
    (void)workspace;
    const sep_size_t n = zp->n;
    const sep_u64 f_negative = f >> 63;
    const sep_u64 g_negative = g >> 63;
    sep_u64 left[n];
    sep_u64 right[n];
    scalar_mod(zp, left, a, f_negative != 0 ? 0 - f : f);
    scalar_mod(zp, right, b, g_negative != 0 ? 0 - g : g);
    sep_cczp_cond_negate(zp, f_negative, left, left);
    sep_cczp_cond_negate(zp, g_negative, right, right);
    sep_cczp_add_default_ws(NULL, zp, result, left, right);
    for (sep_size_t i = 0; i < 31; ++i) {
        sep_cczp_div2_ws(NULL, zp, result, result);
    }
}

int sep_cczp_inv_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    return zp_funcs(zp)->inv(workspace, zp, result, value);
}

int sep_cczp_inv_field_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    const sep_size_t n = zp->n;
    const sep_u64 *exponent = sep_cczp_prime(zp) + 2 * n + 1;
    if (n == 0 || sep_ccn_bitlen(n, exponent) < 2 ||
        (sep_ccn_n(n, sep_cczp_prime(zp)) <= 1 &&
         sep_cczp_prime(zp)[0] < 2)) {
        return SEP_CCERR_INTERNAL;
    }
    sep_u64 encoded[n];
    sep_u64 powered[n];
    sep_cczp_to_ws(workspace, zp, encoded, value);
    const int status = sep_cczp_power_fast_ws(
        workspace,
        zp,
        powered,
        encoded,
        exponent
    );
    sep_cczp_from_ws(workspace, zp, result, powered);
    return status;
}

int sep_cczp_is_quadratic_residue_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    const sep_u64 *value
) {
    const sep_size_t n = zp->n;
    sep_u64 exponent[n];
    sep_u64 powered[n];
    sep_u64 affine[n];
    copy_limbs(n, exponent, sep_cczp_prime(zp));
    exponent[0] &= ~(sep_u64)1;
    (void)sep_ccn_shift_right(n, exponent, exponent, 1);
    if (sep_cczp_power_fast_ws(workspace, zp, powered, value, exponent) != 0) {
        return -1;
    }
    sep_cczp_from_ws(workspace, zp, affine, powered);
    return is_one(n, affine) ? 0 : -1;
}

int sep_cczp_sqrt_tonelli_shanks_precomp_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value,
    sep_size_t c1,
    const sep_u64 *c3,
    const sep_u64 *c5
) {
    const sep_size_t n = zp->n;
    sep_u64 t[n];
    sep_u64 b[n];
    sep_u64 c[n];
    sep_u64 one[n];
    (void)sep_cczp_power_fast_ws(workspace, zp, result, value, c3);
    sep_ccn_seti(n, one, 1);
    sep_cczp_to_ws(workspace, zp, one, one);
    copy_limbs(n, c, c5);
    sep_cczp_sqr_ws(workspace, zp, t, result);
    sep_cczp_mul_ws(workspace, zp, t, t, value);
    sep_cczp_mul_ws(workspace, zp, result, result, value);

    for (sep_size_t k = c1; k >= 2; --k) {
        copy_limbs(n, b, t);
        for (sep_size_t j = 1; j < k - 1; ++j) {
            sep_cczp_sqr_ws(workspace, zp, b, b);
        }
        if (sep_ccn_cmp_internal(n, b, one) != 0) {
            sep_cczp_mul_ws(workspace, zp, result, result, c);
        }
        sep_cczp_sqr_ws(workspace, zp, c, c);
        if (sep_ccn_cmp_internal(n, b, one) != 0) {
            sep_cczp_mul_ws(workspace, zp, t, t, c);
        }
    }
    sep_cczp_sqr_ws(workspace, zp, b, result);
    return sep_ccn_cmp_internal(n, b, value) == 0 ? 0 : SEP_CCERR_PARAMETER;
}

int sep_cczp_sqrt_default_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    const sep_size_t n = zp->n;
    const sep_u64 *prime = sep_cczp_prime(zp);
    if ((prime[0] & 3) == 3) {
        sep_u64 exponent[n];
        sep_u64 check[n];
        (void)sep_ccn_add1(n, exponent, prime, 1);
        (void)sep_ccn_shift_right(n, exponent, exponent, 2);
        (void)sep_cczp_power_fast_ws(
            workspace,
            zp,
            result,
            value,
            exponent
        );
        sep_cczp_sqr_ws(workspace, zp, check, result);
        return sep_ccn_cmp_internal(n, check, value) == 0
            ? 0
            : SEP_CCERR_PARAMETER;
    }

    sep_u64 odd_part[n];
    copy_limbs(n, odd_part, prime);
    odd_part[0] &= ~(sep_u64)1;
    sep_size_t c1 = 0;
    while (((odd_part[c1 >> 6] >> (c1 & 63)) & 1) == 0) {
        ++c1;
    }
    sep_ccn_shift_right_multi(n, odd_part, odd_part, c1);
    sep_u64 c3[n];
    (void)sep_ccn_sub1(n, c3, odd_part, 1);
    (void)sep_ccn_shift_right(n, c3, c3, 1);
    sep_u64 c5[n];
    sep_ccn_seti(n, c5, 1);
    while (sep_cczp_is_quadratic_residue_ws(workspace, zp, c5) == 0) {
        (void)sep_ccn_add1(n, c5, c5, 1);
    }
    (void)sep_cczp_power_fast_ws(workspace, zp, c5, c5, odd_part);
    return sep_cczp_sqrt_tonelli_shanks_precomp_ws(
        workspace,
        zp,
        result,
        value,
        c1,
        c3,
        c5
    );
}

int sep_cczp_sqrt_ws(
    sep_cc_ws_t *workspace,
    const sep_cczp_t *zp,
    sep_u64 *result,
    const sep_u64 *value
) {
    return zp_funcs(zp)->sqrt(workspace, zp, result, value);
}

int sep_cczp_init_ws(sep_cc_ws_t *workspace, sep_cczp_t *zp) {
    (void)workspace;
    const sep_size_t n = zp->n;
    const sep_u64 *prime = sep_cczp_prime(zp);
    if ((prime[0] & 1) == 0 ||
        (sep_ccn_n(n, prime) == 1 && prime[0] < 3)) {
        return SEP_CCERR_PARAMETER;
    }
    zp->funcs = &default_funcs;
    zp->bitlen = sep_ccn_bitlen(n, prime);
    sep_u64 inverse = 1;
    for (sep_size_t i = 0; i < 6; ++i) {
        inverse *= 2 - prime[0] * inverse;
    }
    *zp_p0inv(zp) = 0 - inverse;
    sep_u64 *r2 = zp_p0inv(zp) + 1;
    sep_ccn_seti(n, r2, 1);
    for (sep_size_t i = 0; i < 128 * n; ++i) {
        sep_cczp_add_default_ws(NULL, zp, r2, r2, r2);
    }
    return 0;
}

int sep_cczp_mm_init_ws(
    sep_cc_ws_t *workspace,
    sep_cczp_t *zp,
    sep_size_t limb_count,
    const sep_u64 *prime
) {
    zp->n = limb_count;
    if (prime != NULL) {
        copy_limbs(limb_count, zp_payload(zp), prime);
    }
    const int status = sep_cczp_init_ws(workspace, zp);
    zp->funcs = &montgomery_funcs;
    return status;
}

static const sep_cczp_funcs_t default_funcs = {
    .add = sep_cczp_add_default_ws,
    .sub = sep_cczp_sub_default_ws,
    .mul = sep_cczp_mul_default_ws,
    .sqr = sep_cczp_sqr_default_ws,
    .mod = sep_cczp_mod_default_ws,
    .inv = sep_cczp_inv_default_ws,
    .sqrt = sep_cczp_sqrt_default_ws,
    .to = sep_cczp_to_default_ws,
    .from = sep_cczp_from_default_ws,
};

static const sep_cczp_funcs_t montgomery_funcs = {
    .add = sep_cczp_add_default_ws,
    .sub = sep_cczp_sub_default_ws,
    .mul = sep_cczp_mm_mul_ws,
    .sqr = sep_cczp_mm_sqr_ws,
    .mod = sep_cczp_mm_mod_ws,
    .inv = sep_cczp_inv_default_ws,
    .sqrt = sep_cczp_sqrt_default_ws,
    .to = sep_cczp_mm_to_ws,
    .from = sep_cczp_mm_from_ws,
};
