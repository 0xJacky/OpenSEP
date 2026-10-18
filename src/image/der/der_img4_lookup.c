#include "open_secure_rom/der.h"

int sep_der_img4_decode_content_find_item_with_tag(
    const sep_der_item_t *content,
    sep_u64 tag,
    sep_der_item_t *item
) {
    sep_der_sequence_t sequence;
    int result = sep_der_decode_sequence_content_init(content, &sequence);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    sep_der_decoded_info_t decoded = {0};
    while ((result = sep_der_decode_sequence_next(&sequence, &decoded)) ==
        SEP_DER_SUCCESS) {
        if (decoded.tag == tag) {
            *item = decoded.content;
            return SEP_DER_SUCCESS;
        }
    }
    return result;
}

int sep_der_img4_decode_tag_compare(
    const sep_der_item_t *item,
    sep_u32 magic
) {
    if (item->length < 4) {
        return -1;
    }
    if (item->length > 4) {
        return 1;
    }

    sep_u32 value = 0;
    if (sep_der_parse_integer(item, &value) != SEP_DER_SUCCESS) {
        return -2;
    }
    if (value < magic) {
        return -1;
    }
    return value > magic;
}

int sep_der_img4_decode_property_with_item(
    const sep_der_item_t *property,
    sep_u64 expected_tag,
    sep_u64 value_tag,
    sep_img4_der_element_t output[2]
) {
    const sep_der_item_spec_t specs[2] = {
        {0, 0x16, 0},
        {sizeof(sep_img4_der_element_t), value_tag, 0},
    };
    int result = sep_der_parse_sequence_to_object(
        property,
        2,
        specs,
        output,
        sizeof(sep_img4_der_element_t) * 2,
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    sep_u32 value = 0;
    result = sep_der_parse_integer(&output[0].item, &value);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (((sep_u64)value | 0xe000000000000000ULL) != expected_tag) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    output[0].tag = expected_tag | 0xe000000000000000ULL;
    output[1].tag = value_tag;
    return SEP_DER_SUCCESS;
}

int sep_der_img4_decode_find_property_in_sequence(
    sep_der_sequence_t *sequence,
    sep_u64 expected_tag,
    sep_u64 value_tag,
    sep_img4_der_element_t output[2]
) {
    sep_der_decoded_info_t decoded = {0};
    int result;
    while ((result = sep_der_decode_sequence_next(sequence, &decoded)) ==
        SEP_DER_SUCCESS) {
        if (decoded.tag == expected_tag) {
            return sep_der_img4_decode_property_with_item(
                &decoded.content,
                expected_tag,
                value_tag,
                output
            );
        }
    }
    return result;
}

int sep_der_img4_decode_find_property(
    const sep_der_item_t *content,
    sep_u64 expected_tag,
    sep_u64 value_tag,
    sep_img4_der_element_t output[2]
) {
    sep_der_sequence_t sequence;
    const int result = sep_der_decode_sequence_content_init(content, &sequence);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    return sep_der_img4_decode_find_property_in_sequence(
        &sequence,
        expected_tag,
        value_tag,
        output
    );
}
