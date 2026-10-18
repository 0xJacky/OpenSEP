#include "open_secure_rom/bignum.h"

#include "open_secure_rom/runtime.h"

int sep_cc_cmp_safe_internal(
    sep_size_t length,
    const void *left,
    const void *right
) {
    if (length == 0) {
        return 1;
    }
    const sep_u8 *left_bytes = left;
    const sep_u8 *right_bytes = right;
    sep_u8 difference = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        difference |= left_bytes[index] ^ right_bytes[index];
    }
    return difference != 0;
}

int sep_cc_cmp_safe(
    sep_size_t length,
    const void *left,
    const void *right
) {
    return sep_cc_cmp_safe_internal(length, left, right);
}

int sep_ccn_cmp_asm(
    sep_size_t limb_count,
    const sep_u64 *left,
    const sep_u64 *right
) {
    for (sep_size_t index = limb_count; index != 0; --index) {
        if (left[index - 1] > right[index - 1]) {
            return 1;
        }
        if (left[index - 1] < right[index - 1]) {
            return -1;
        }
    }
    return 0;
}

int sep_ccn_cmp_public_value(
    sep_size_t limb_count,
    const sep_u64 *s,
    const sep_u64 *t
) {
    return sep_ccn_cmp_asm(limb_count, s, t);
}

int sep_ccn_cmp_internal(
    sep_size_t limb_count,
    const sep_u64 *s,
    const sep_u64 *t
) {
    return sep_ccn_cmp_public_value(limb_count, s, t);
}

int sep_ccn_cmpn_public_value(
    sep_size_t s_limb_count,
    const sep_u64 *s,
    sep_size_t t_limb_count,
    const sep_u64 *t
) {
    const sep_size_t common = s_limb_count < t_limb_count
        ? s_limb_count
        : t_limb_count;
    if (s_limb_count > common &&
        sep_ccn_n(s_limb_count - common, s + common) != 0) {
        return 1;
    }
    if (t_limb_count > common &&
        sep_ccn_n(t_limb_count - common, t + common) != 0) {
        return -1;
    }
    return sep_ccn_cmp_public_value(common, s, t);
}

int sep_ccn_cmpn_internal(
    sep_size_t s_limb_count,
    const sep_u64 *s,
    sep_size_t t_limb_count,
    const sep_u64 *t
) {
    return sep_ccn_cmpn_public_value(s_limb_count, s, t_limb_count, t);
}

sep_size_t sep_ccn_n_asm(
    sep_size_t limb_count,
    const sep_u64 *limbs
) {
    while (limb_count != 0 && limbs[limb_count - 1] == 0) {
        --limb_count;
    }
    return limb_count;
}

sep_size_t sep_ccn_n(
    sep_size_t limb_count,
    const sep_u64 *limbs
) {
    return sep_ccn_n_asm(limb_count, limbs);
}

sep_size_t sep_ccn_bitlen_internal(
    sep_size_t limb_count,
    const sep_u64 *limbs
) {
    limb_count = sep_ccn_n(limb_count, limbs);
    if (limb_count == 0) {
        return 0;
    }
    return (limb_count - 1) * 64 +
        (64 - (sep_size_t)__builtin_clzll(limbs[limb_count - 1]));
}

sep_size_t sep_ccn_bitlen(
    sep_size_t limb_count,
    const sep_u64 *limbs
) {
    return sep_ccn_bitlen_internal(limb_count, limbs);
}

sep_size_t sep_bignum_bit_length(
    sep_size_t limb_count,
    const sep_u64 *limbs
) {
    return sep_ccn_bitlen_internal(limb_count, limbs);
}

sep_size_t sep_cczp_n(const sep_cczp_t *zp) {
    return zp->n;
}

sep_size_t sep_cczp_bitlen(const sep_cczp_t *zp) {
    return zp->bitlen;
}

void sep_ccn_set_bit(
    sep_u64 *limbs,
    sep_size_t bit_index,
    sep_u64 value
) {
    const sep_u64 mask = (sep_u64)1 << (bit_index & 63);
    sep_u64 *limb = &limbs[bit_index >> 6];
    *limb = (*limb & ~mask) | ((0 - (value & 1)) & mask);
}
