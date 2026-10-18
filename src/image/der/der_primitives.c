#include "open_secure_rom/der.h"

int sep_der_parse_bit_string(
    const sep_der_item_t *contents,
    sep_der_item_t *bit_string_bytes,
    sep_u8 *unused_bit_count
) {
    *unused_bit_count = 0;
    bit_string_bytes->data = 0;
    bit_string_bytes->length = 0;
    if (contents->length == 0) {
        return SEP_DER_DECODE_ERROR;
    }

    const sep_u8 unused = contents->data[0];
    *unused_bit_count = unused;
    if (contents->length == 1) {
        return unused == 0 ? SEP_DER_SUCCESS : SEP_DER_DECODE_ERROR;
    }
    if (unused > 7) {
        return SEP_DER_DECODE_ERROR;
    }

    const sep_u8 trailing_mask = (sep_u8)(0xffU >> (8U - unused));
    if ((contents->data[contents->length - 1] & trailing_mask) != 0) {
        return SEP_DER_DECODE_ERROR;
    }

    bit_string_bytes->data = contents->data + 1;
    bit_string_bytes->length = contents->length - 1;
    return SEP_DER_SUCCESS;
}

int sep_der_parse_boolean(
    const sep_der_item_t *contents,
    sep_bool *value
) {
    if (contents->length != 1 ||
        (contents->data[0] != 0 && contents->data[0] != 0xffU)) {
        return SEP_DER_DECODE_ERROR;
    }
    *value = contents->data[0] != 0;
    return SEP_DER_SUCCESS;
}

int sep_der_parse_integer64(
    const sep_der_item_t *contents,
    sep_u64 *value
) {
    const sep_u8 *data = contents->data;
    sep_size_t length = contents->length;
    if (length == 0 || (data[0] & 0x80U) != 0) {
        return SEP_DER_DECODE_ERROR;
    }

    if (data[0] == 0) {
        if (length != 1) {
            if ((data[1] & 0x80U) == 0) {
                return SEP_DER_DECODE_ERROR;
            }
            if (length > 9) {
                return SEP_DER_BUFFER_OVERFLOW;
            }
        }
    } else if (length > 8) {
        return SEP_DER_BUFFER_OVERFLOW;
    }

    sep_u64 decoded = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        decoded = (decoded << 8) | data[index];
    }
    *value = decoded;
    return SEP_DER_SUCCESS;
}

int sep_der_parse_integer(
    const sep_der_item_t *contents,
    sep_u32 *value
) {
    sep_u64 decoded;
    const int result = sep_der_parse_integer64(contents, &decoded);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if ((decoded >> 32) != 0) {
        return SEP_DER_BUFFER_OVERFLOW;
    }
    *value = (sep_u32)decoded;
    return SEP_DER_SUCCESS;
}
