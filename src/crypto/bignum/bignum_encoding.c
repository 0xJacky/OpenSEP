#include "open_secure_rom/bignum.h"

#include "open_secure_rom/runtime.h"

void sep_ccn_shift_right_asm(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *source,
    sep_size_t shift
) {
    if (shift == 0) {
        sep_memmove(result, source, limb_count * sizeof(*result));
        return;
    }
    if (shift >= 64) {
        sep_ccn_zero(limb_count, result);
        return;
    }
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const sep_u64 high = index + 1 < limb_count ? source[index + 1] : 0;
        result[index] = (source[index] >> shift) | (high << (64 - shift));
    }
}

sep_u64 sep_ccn_shift_right(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *value,
    sep_size_t bit_count
) {
    if (limb_count != 0) {
        sep_ccn_shift_right_asm(limb_count, result, value, bit_count);
    }
    return limb_count;
}

void sep_ccn_shift_right_multi(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *value,
    sep_size_t bit_count
) {
    const sep_size_t word_shift = bit_count >> 6;
    const sep_size_t bit_shift = bit_count & 63;
    for (sep_size_t index = 0; index < limb_count; ++index) {
        const sep_size_t source_index = index + word_shift;
        sep_u64 output = 0;
        if (source_index < limb_count) {
            output = value[source_index] >> bit_shift;
            if (bit_shift != 0 && source_index + 1 < limb_count) {
                output |= value[source_index + 1] << (64 - bit_shift);
            }
        }
        result[index] = output;
    }
}

void sep_ccn_shift_left(
    sep_size_t limb_count,
    sep_u64 *result,
    const sep_u64 *value,
    sep_size_t bit_count
) {
    if (bit_count == 0) {
        sep_memmove(result, value, limb_count * sizeof(*result));
        return;
    }
    if (bit_count >= 64) {
        sep_ccn_zero(limb_count, result);
        return;
    }
    for (sep_size_t index = limb_count; index != 0; --index) {
        const sep_u64 low = index > 1 ? value[index - 2] : 0;
        result[index - 1] = (value[index - 1] << bit_count) |
            (low >> (64 - bit_count));
    }
}

int sep_ccn_read_uint_public_value(
    sep_size_t limb_count,
    sep_u64 *destination,
    sep_size_t input_length,
    const sep_u8 *input
) {
    const sep_size_t capacity = limb_count * sizeof(*destination);
    if (input_length > capacity) {
        const sep_size_t excess = input_length - capacity;
        for (sep_size_t index = 0; index < excess; ++index) {
            if (input[index] != 0) {
                return -7;
            }
        }
        input += excess;
        input_length = capacity;
    }
    sep_ccn_zero(limb_count, destination);
    for (sep_size_t index = 0; index < input_length; ++index) {
        const sep_size_t reverse_index = input_length - 1 - index;
        destination[index >> 3] |=
            (sep_u64)input[reverse_index] << ((index & 7) * 8);
    }
    return 0;
}

int sep_ccn_read_uint(
    sep_size_t limb_count,
    sep_u64 *destination,
    sep_size_t input_length,
    const sep_u8 *input
) {
    return sep_ccn_read_uint_public_value(
        limb_count,
        destination,
        input_length,
        input
    );
}

sep_size_t sep_ccn_write_uint_size(
    sep_size_t limb_count,
    const sep_u64 *limbs
) {
    return (sep_ccn_bitlen_internal(limb_count, limbs) + 7) >> 3;
}

void sep_ccn_write_uint_public_value(
    sep_size_t limb_count,
    const sep_u64 *limbs,
    sep_size_t output_length,
    void *output
) {
    const sep_size_t significant = sep_ccn_write_uint_size(limb_count, limbs);
    const sep_size_t written = output_length < significant
        ? output_length
        : significant;
    sep_u8 *bytes = output;
    for (sep_size_t index = 0; index < written; ++index) {
        const sep_size_t source_byte = significant - 1 - index;
        bytes[index] = (sep_u8)(
            limbs[source_byte >> 3] >> ((source_byte & 7) * 8)
        );
    }
}

void sep_ccn_write_uint_internal(
    sep_size_t limb_count,
    const sep_u64 *limbs,
    sep_size_t output_length,
    void *output
) {
    sep_ccn_write_uint_public_value(
        limb_count,
        limbs,
        output_length,
        output
    );
}

int sep_ccn_write_uint_padded_ct_internal(
    sep_size_t limb_count,
    const sep_u64 *limbs,
    sep_size_t output_length,
    sep_u8 *output
) {
    if (limb_count > 0x0fffffff) {
        return -7;
    }
    const sep_size_t significant = sep_ccn_write_uint_size(limb_count, limbs);
    if (output_length < significant) {
        return -7;
    }
    sep_memzero(output, output_length);
    sep_ccn_write_uint_public_value(
        limb_count,
        limbs,
        significant,
        output + output_length - significant
    );
    return (int)(output_length - significant);
}

int sep_ccn_write_uint_padded_ct(
    sep_size_t limb_count,
    const sep_u64 *limbs,
    sep_size_t output_length,
    sep_u8 *output
) {
    return sep_ccn_write_uint_padded_ct_internal(
        limb_count,
        limbs,
        output_length,
        output
    );
}

sep_size_t sep_ccn_write_uint_padded_internal(
    sep_size_t limb_count,
    const sep_u64 *limbs,
    sep_size_t output_length,
    sep_u8 *output
) {
    const int padding = sep_ccn_write_uint_padded_ct(
        limb_count,
        limbs,
        output_length,
        output
    );
    if (padding >= 0) {
        return (sep_size_t)padding;
    }
    sep_ccn_write_uint_internal(limb_count, limbs, output_length, output);
    return 0;
}

sep_size_t sep_ccn_write_uint_padded(
    sep_size_t limb_count,
    const sep_u64 *limbs,
    sep_size_t output_length,
    sep_u8 *output
) {
    return sep_ccn_write_uint_padded_internal(
        limb_count,
        limbs,
        output_length,
        output
    );
}

void sep_ccn_swap(sep_size_t limb_count, sep_u64 *limbs) {
    for (sep_size_t left = 0, right = limb_count == 0 ? 0 : limb_count - 1;
         left < right;
         ++left, --right) {
        const sep_u64 left_value = __builtin_bswap64(limbs[left]);
        limbs[left] = __builtin_bswap64(limbs[right]);
        limbs[right] = left_value;
    }
    if ((limb_count & 1) != 0) {
        limbs[limb_count >> 1] = __builtin_bswap64(limbs[limb_count >> 1]);
    }
}
