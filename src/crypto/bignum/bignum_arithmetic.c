#include "open_secure_rom/bignum.h"

#include "open_secure_rom/crypto_workspace.h"
#include "open_secure_rom/runtime.h"

extern sep_u64 sep_xorshift64_state;

sep_u64 sep_ccn_mul1_asm(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *source,
    sep_u64 multiplier
) {
    sep_u64 carry = 0;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const unsigned __int128 product =
            (unsigned __int128)source[index] * multiplier + carry;
        result[index] = (sep_u64)product;
        carry = (sep_u64)(product >> 64);
    }
    return carry;
}

sep_u64 sep_ccn_mul1_veneer(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *source,
    sep_u64 multiplier
) {
    return sep_ccn_mul1_asm(limb_count, result, source, multiplier);
}

sep_u64 sep_ccn_addmul1_asm(
    sep_size_t limb_count,
    sep_u64 *destination,
    const sep_u64 *source,
    sep_u64 word
) {
    sep_u64 carry = 0;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const unsigned __int128 value =
            (unsigned __int128)source[index] * word +
            destination[index] + carry;
        destination[index] = (sep_u64)value;
        carry = (sep_u64)(value >> 64);
    }
    return carry;
}

sep_u64 sep_ccn_addmul1(
    sep_size_t limb_count,
    sep_u64 *destination,
    const sep_u64 *source,
    sep_u64 word
) {
    return sep_ccn_addmul1_asm(limb_count, destination, source, word);
}

sep_u64 sep_ccn_add1(
    sep_size_t limb_count,
    sep_u64 *destination,
    const sep_u64 *source,
    sep_u64 word
) {
    sep_u64 carry = word;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const sep_u64 value = source[index];
        destination[index] = value + carry;
        carry = destination[index] < value;
    }
    return carry;
}

sep_u64 sep_ccn_add1_ws(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count,
    sep_u64 *destination,
    const sep_u64 *source,
    sep_u64 word
) {
    (void)workspace;
    return sep_ccn_add1(limb_count, destination, source, word);
}

sep_u64 sep_ccn_sub1(
    sep_size_t limb_count,
    sep_u64 *destination,
    const sep_u64 *source,
    sep_u64 word
) {
    sep_u64 borrow = word;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const sep_u64 value = source[index];
        destination[index] = value - borrow;
        borrow = value < borrow;
    }
    return borrow;
}

sep_u64 sep_ccn_add(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *s,
    const sep_u64 *t
) {
    sep_u64 carry = 0;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const unsigned __int128 value =
            (unsigned __int128)s[index] + t[index] + carry;
        result[index] = (sep_u64)value;
        carry = (sep_u64)(value >> 64);
    }
    return carry;
}

sep_u64 sep_ccn_add_ws(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *s,
    const sep_u64 *t
) {
    (void)workspace;
    return sep_ccn_add(limb_count, result, s, t);
}

sep_u64 sep_ccn_sub(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *s,
    const sep_u64 *t
) {
    sep_u64 borrow = 0;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const unsigned __int128 subtrahend =
            (unsigned __int128)t[index] + borrow;
        result[index] = s[index] - (sep_u64)subtrahend;
        borrow = (unsigned __int128)s[index] < subtrahend;
    }
    return borrow;
}

sep_u64 sep_ccn_sub_ws(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *s,
    const sep_u64 *t
) {
    (void)workspace;
    return sep_ccn_sub(limb_count, result, s, t);
}

sep_u64 sep_ccn_subn(
    sep_size_t result_limb_count,
    sep_u64 *result,
    const sep_u64 *s,
    sep_size_t t_limb_count,
    const sep_u64 *t
) {
    sep_u64 borrow = sep_ccn_sub(t_limb_count, result, s, t);
    return sep_ccn_sub1(
        result_limb_count - t_limb_count,
        result + t_limb_count,
        s + t_limb_count,
        borrow
    );
}

void sep_ccn_mul(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *left,
    const sep_u64 *right
) {
    sep_memzero(result, 2 * limb_count * sizeof(*result));
    for (sep_size_t left_index = 0; left_index < limb_count; ++left_index) {
        sep_u64 carry = 0;
        for (sep_size_t right_index = 0; right_index < limb_count;
             ++right_index) {
            const sep_size_t output_index = left_index + right_index;
            const unsigned __int128 value =
                (unsigned __int128)left[left_index] * right[right_index] +
                result[output_index] + carry;
            result[output_index] = (sep_u64)value;
            carry = (sep_u64)(value >> 64);
        }
        result[left_index + limb_count] = carry;
    }
}

void sep_ccn_sqr_ws(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count,
    sep_u64 *double_width_result,
    const sep_u64 *value
) {
    (void)workspace;
    sep_ccn_mul(limb_count, double_width_result, value, value);
}

void sep_ccn_zero(sep_size_t limb_count, sep_u64 *limbs) {
    sep_memzero(limbs, limb_count * sizeof(*limbs));
}

void sep_ccn_seti(
    sep_size_t limb_count,
    sep_u64 *limbs,
    sep_u64 word
) {
    sep_ccn_zero(limb_count, limbs);
    if (limb_count != 0) {
        limbs[0] = word;
    }
}

void sep_ccn_neg(
    sep_size_t limb_count,
    sep_u64 *destination,
    const sep_u64 *source
) {
    for (sep_size_t index = 0; index < limb_count; ++index) {
        destination[index] = ~source[index];
    }
    (void)sep_ccn_add1(limb_count, destination, destination, 1);
}

void sep_ccn_cond_neg(
    sep_size_t limb_count,
    sep_u64 condition,
    sep_u64 *result,
    const sep_u64 *value
) {
    const sep_u64 mask = 0 - (condition & 1);
    sep_u64 carry = condition & 1;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const sep_u64 selected = value[index] ^ mask;
        const sep_u64 output = selected + carry;
        carry = output < selected;
        result[index] = output;
    }
}

sep_u64 sep_ccn_cond_add(
    sep_size_t limb_count,
    sep_u64 condition,
    sep_u64 *result,
    const sep_u64 *x,
    const sep_u64 *y
) {
    const sep_u64 mask = 0 - (condition & 1);
    sep_u64 carry = 0;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const unsigned __int128 value =
            (unsigned __int128)x[index] + (y[index] & mask) + carry;
        result[index] = (sep_u64)value;
        carry = (sep_u64)(value >> 64);
    }
    return carry & condition;
}

sep_u64 sep_ccn_cond_rsub(
    sep_size_t limb_count,
    sep_u64 condition,
    sep_u64 *result,
    const sep_u64 *left,
    const sep_u64 *right
) {
    const sep_u64 mask = 0 - (condition & 1);
    sep_u64 borrow = 0;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const unsigned __int128 subtrahend =
            (unsigned __int128)left[index] + borrow;
        const sep_u64 difference = right[index] - (sep_u64)subtrahend;
        borrow = (unsigned __int128)right[index] < subtrahend;
        result[index] = (left[index] & ~mask) | (difference & mask);
    }
    return borrow & condition;
}

void sep_ccn_cond_clear(
    sep_size_t limb_count,
    sep_u64 condition,
    sep_u64 *value
) {
    const sep_u64 mask = ~(0 - (condition & 1));
    for (sep_size_t index = 0; index < limb_count; ++index) {
        value[index] &= mask;
    }
}

void sep_ccn_cond_swap(
    sep_size_t limb_count,
    sep_u64 selector,
    sep_u64 *left,
    sep_u64 *right
) {
    const sep_u64 mask = 0 - (selector & 1);
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const sep_u64 difference = (left[index] ^ right[index]) & mask;
        left[index] ^= difference;
        right[index] ^= difference;
    }
}

void sep_ccn_mux(
    sep_size_t limb_count,
    sep_u64 selector,
    sep_u64 *result,
    const sep_u64 *selected_when_one,
    const sep_u64 *selected_when_zero
) {
    const sep_u64 mask = 0 - (selector & 1);
    for (sep_size_t index = 0; index < limb_count; ++index) {
        result[index] = (selected_when_one[index] & mask) |
            (selected_when_zero[index] & ~mask);
    }
}

void sep_ccn_mux_seed_mask(sep_u64 seed) {
    sep_xorshift64_state ^= seed;
}
