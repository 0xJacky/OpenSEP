#include "open_secure_rom/der.h"

#include <stdint.h>

_Static_assert(sizeof(sep_der_item_t) == 16, "DER item ABI size");
_Static_assert(sizeof(sep_der_decoded_info_t) == 24, "DER decoded ABI size");
_Static_assert(sizeof(sep_der_sequence_t) == 16, "DER sequence ABI size");
_Static_assert(sizeof(sep_der_item_spec_t) == 24, "DER item spec ABI size");
_Static_assert(sizeof(sep_img4_der_element_t) == 24, "IMG4 DER element ABI size");

typedef struct sep_der_header {
    sep_u64 tag;
    sep_size_t content_offset;
    sep_size_t content_length;
} sep_der_header_t;

static void der_trap(void) {
    __builtin_trap();
}

static void der_zero(void *destination, sep_size_t length) {
    sep_u8 *bytes = destination;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

static int der_constant_time_compare(
    const sep_u8 *left,
    const sep_u8 *right,
    sep_size_t length
) {
    sep_u8 difference = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference;
}

static uintptr_t der_checked_end(const sep_u8 *data, sep_size_t length) {
    const uintptr_t address = (uintptr_t)data;
    if (length > UINTPTR_MAX - address) {
        der_trap();
    }
    return address + length;
}

static int der_decode_header(
    const sep_der_item_t *der,
    sep_der_decoded_info_t *decoded,
    sep_der_header_t *header
) {
    const sep_u8 *data = der->data;
    const sep_size_t length = der->length;
    sep_size_t cursor = 0;
    sep_u64 tag_number;

    der_checked_end(data, length);
    if (length < 2) {
        return SEP_DER_DECODE_ERROR;
    }

    const sep_u8 first_tag_byte = data[cursor++];
    tag_number = first_tag_byte & 0x1fU;
    if (tag_number == 0x1fU) {
        const sep_u8 first_long_tag_byte = data[cursor];
        if (first_long_tag_byte == 0x80U || first_long_tag_byte < 0x1fU) {
            return SEP_DER_DECODE_ERROR;
        }

        tag_number = 0;
        sep_u8 tag_byte;
        do {
            /* One byte must remain for the length encoding. */
            if (length - cursor < 2 || (tag_number >> 57) != 0) {
                return SEP_DER_DECODE_ERROR;
            }
            tag_byte = data[cursor++];
            tag_number = (tag_number << 7) | (tag_byte & 0x7fU);
        } while ((tag_byte & 0x80U) != 0);

        if ((tag_number >> 61) != 0) {
            return SEP_DER_DECODE_ERROR;
        }
    }

    header->tag = tag_number | ((sep_u64)(first_tag_byte & 0xe0U) << 56);
    decoded->tag = header->tag;

    const sep_u8 first_length_byte = data[cursor++];
    if ((first_length_byte & 0x80U) == 0) {
        header->content_offset = cursor;
        header->content_length = first_length_byte;
        return SEP_DER_SUCCESS;
    }

    const sep_size_t length_byte_count = first_length_byte & 0x7fU;
    if (length_byte_count == 0 || length_byte_count > sizeof(sep_size_t) ||
        length - cursor < length_byte_count || data[cursor] == 0) {
        return SEP_DER_DECODE_ERROR;
    }

    sep_size_t content_length = 0;
    for (sep_size_t index = 0; index < length_byte_count; ++index) {
        content_length = (content_length << 8) | data[cursor++];
    }
    if (content_length < 0x80) {
        return SEP_DER_DECODE_ERROR;
    }

    header->content_offset = cursor;
    header->content_length = content_length;
    return SEP_DER_SUCCESS;
}

int sep_der_decode_item_partial_buffer_get_length(
    const sep_der_item_t *der,
    sep_der_decoded_info_t *decoded,
    sep_size_t *encoded_length
) {
    sep_der_header_t header;
    const int result = der_decode_header(der, decoded, &header);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    const sep_size_t available_content = der->length - header.content_offset;
    if (encoded_length == 0 && header.content_length > available_content) {
        return SEP_DER_DECODE_ERROR;
    }

    decoded->content.data = der->data + header.content_offset;
    decoded->content.length = header.content_length < available_content
        ? header.content_length
        : available_content;
    if (encoded_length != 0) {
        *encoded_length = header.content_length;
    }
    return SEP_DER_SUCCESS;
}

int sep_der_decode_item(
    const sep_der_item_t *der,
    sep_der_decoded_info_t *decoded
) {
    return sep_der_decode_item_partial_buffer_get_length(der, decoded, 0);
}

int sep_der_decode_item_partial_buffer(
    const sep_der_item_t *der,
    sep_der_decoded_info_t *decoded,
    sep_bool allow_partial_buffer
) {
    sep_der_header_t header;
    const int result = der_decode_header(der, decoded, &header);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    const sep_size_t available_content = der->length - header.content_offset;
    if ((allow_partial_buffer & 1U) == 0 &&
        header.content_length > available_content) {
        return SEP_DER_DECODE_ERROR;
    }

    const uintptr_t content_address =
        (uintptr_t)der->data + header.content_offset;
    if (content_address > INTPTR_MAX ||
        header.content_length > (sep_size_t)INTPTR_MAX - content_address) {
        return SEP_DER_BUFFER_OVERFLOW;
    }

    decoded->content.data = (const sep_u8 *)content_address;
    decoded->content.length = header.content_length;
    return SEP_DER_SUCCESS;
}

sep_bool sep_der_sequence_encoded_length(
    const sep_u8 *data,
    sep_size_t available,
    sep_size_t *encoded_length
) {
    const sep_der_item_t der = {data, available};
    sep_der_decoded_info_t decoded = {0};
    if (sep_der_decode_item_partial_buffer(&der, &decoded, 1) !=
            SEP_DER_SUCCESS ||
        decoded.tag != SEP_DER_TAG_SEQUENCE) {
        return 0;
    }

    const sep_size_t header_length =
        (sep_size_t)((uintptr_t)decoded.content.data - (uintptr_t)data);
    if (decoded.content.length > SIZE_MAX - header_length) {
        der_trap();
    }
    if (encoded_length == 0 || ((uintptr_t)encoded_length & 7U) != 0) {
        der_trap();
    }
    *encoded_length = header_length + decoded.content.length;
    return 1;
}

int sep_der_decode_sequence_init(
    const sep_der_item_t *der,
    sep_u64 *tag,
    sep_der_sequence_t *sequence
) {
    sep_der_decoded_info_t decoded;
    const int result = sep_der_decode_item(der, &decoded);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    *tag = decoded.tag;
    if (decoded.tag != SEP_DER_TAG_SEQUENCE && decoded.tag != SEP_DER_TAG_SET) {
        return SEP_DER_UNEXPECTED_TAG;
    }
    sequence->next_item = decoded.content.data;
    sequence->end = (const sep_u8 *)der_checked_end(
        decoded.content.data,
        decoded.content.length
    );
    return SEP_DER_SUCCESS;
}

int sep_der_decode_sequence_content_init(
    const sep_der_item_t *content,
    sep_der_sequence_t *sequence
) {
    sequence->next_item = content->data;
    sequence->end = (const sep_u8 *)der_checked_end(
        content->data,
        content->length
    );
    return SEP_DER_SUCCESS;
}

int sep_der_decode_sequence_next(
    sep_der_sequence_t *sequence,
    sep_der_decoded_info_t *decoded
) {
    if (sequence->next_item >= sequence->end) {
        return SEP_DER_END_OF_SEQUENCE;
    }

    const sep_der_item_t item = {
        sequence->next_item,
        (sep_size_t)((uintptr_t)sequence->end -
            (uintptr_t)sequence->next_item),
    };
    const int result = sep_der_decode_item(&item, decoded);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    const uintptr_t next = der_checked_end(
        decoded->content.data,
        decoded->content.length
    );
    if (next > (uintptr_t)sequence->end ||
        next < (uintptr_t)sequence->next_item) {
        der_trap();
    }
    sequence->next_item = (const sep_u8 *)next;
    return SEP_DER_SUCCESS;
}

int sep_der_parse_sequence_content_to_object(
    const sep_der_item_t *content,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    void *destination,
    sep_size_t destination_size,
    sep_size_t size_to_zero
) {
    if (size_to_zero > destination_size) {
        der_trap();
    }
    der_zero(destination, size_to_zero);

    sep_der_sequence_t sequence;
    sep_der_decode_sequence_content_init(content, &sequence);
    sep_u16 spec_index = 0;

    while (spec_index < item_count) {
        const sep_u8 *encoded_item = sequence.next_item;
        sep_der_decoded_info_t decoded;
        const int decode_result = sep_der_decode_sequence_next(
            &sequence,
            &decoded
        );
        if (decode_result == SEP_DER_END_OF_SEQUENCE) {
            for (; spec_index < item_count; ++spec_index) {
                if ((specs[spec_index].options & SEP_DER_OPTIONAL) == 0) {
                    return SEP_DER_INCOMPLETE_SEQUENCE;
                }
            }
            return SEP_DER_SUCCESS;
        }
        if (decode_result != SEP_DER_SUCCESS) {
            return decode_result;
        }

        for (;;) {
            if (spec_index >= item_count) {
                return SEP_DER_UNEXPECTED_TAG;
            }
            const sep_der_item_spec_t *spec = &specs[spec_index];
            if ((spec->options & SEP_DER_ANY_TAG) != 0 ||
                decoded.tag == spec->tag) {
                break;
            }
            if ((spec->options & SEP_DER_OPTIONAL) == 0) {
                return SEP_DER_UNEXPECTED_TAG;
            }
            ++spec_index;
        }

        const sep_der_item_spec_t *spec = &specs[spec_index];
        if ((spec->options & SEP_DER_SKIP) == 0) {
            if (spec->offset > SIZE_MAX - sizeof(sep_der_item_t) ||
                spec->offset + sizeof(sep_der_item_t) > destination_size) {
                return SEP_DER_BUFFER_OVERFLOW;
            }
            sep_der_item_t *output = (sep_der_item_t *)(
                (sep_u8 *)destination + spec->offset
            );
            *output = decoded.content;

            if ((spec->options & SEP_DER_SAVE_ENCODING) != 0) {
                const sep_size_t header_length = (sep_size_t)(
                    (uintptr_t)decoded.content.data -
                    (uintptr_t)encoded_item
                );
                if (output->length > SIZE_MAX - header_length) {
                    der_trap();
                }
                output->data = encoded_item;
                output->length += header_length;
            }
        }

        ++spec_index;
        if (spec_index == item_count) {
            return sequence.next_item == sequence.end
                ? SEP_DER_SUCCESS
                : SEP_DER_DECODE_ERROR;
        }
    }

    return sequence.next_item == sequence.end
        ? SEP_DER_SUCCESS
        : SEP_DER_DECODE_ERROR;
}

int sep_der_parse_sequence_to_object(
    const sep_der_item_t *der,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    void *destination,
    sep_size_t destination_size,
    sep_size_t size_to_zero
) {
    sep_der_decoded_info_t decoded;
    const int result = sep_der_decode_item(der, &decoded);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (decoded.tag != SEP_DER_TAG_SEQUENCE) {
        return SEP_DER_UNEXPECTED_TAG;
    }
    return sep_der_parse_sequence_content_to_object(
        &decoded.content,
        item_count,
        specs,
        destination,
        destination_size,
        size_to_zero
    );
}

int sep_der_parse_sequence(
    const sep_der_item_t *der,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    void *destination,
    sep_size_t size_to_zero
) {
    const uintptr_t address = (uintptr_t)destination;
    if (address > INTPTR_MAX) {
        der_trap();
    }
    return sep_der_parse_sequence_to_object(
        der,
        item_count,
        specs,
        destination,
        (sep_size_t)INTPTR_MAX - address,
        size_to_zero
    );
}

sep_bool sep_der_oid_compare(
    const sep_der_item_t *lhs,
    const sep_der_item_t *rhs
) {
    if (lhs == 0 || rhs == 0 || lhs->length != rhs->length) {
        return 0;
    }
    return der_constant_time_compare(lhs->data, rhs->data, lhs->length) == 0;
}
