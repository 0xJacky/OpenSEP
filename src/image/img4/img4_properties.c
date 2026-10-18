#include "open_secure_rom/img4.h"

#include "open_secure_rom/panic.h"
#include "open_secure_rom/runtime.h"

enum {
    MANP_MAGIC = 0x4d414e50U,
    MANX_MAGIC = 0x6d616e78U,
    OBJP_MAGIC = 0x4f424a50U,
};

int sep_img4_decode_property(
    const sep_der_item_t *property,
    sep_u64 expected_tag,
    sep_img4_der_element_t output[2]
) {
    if (property == NULL || output == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    sep_u64 tag = 0;
    sep_der_sequence_t sequence = {0};
    int result = sep_der_decode_sequence_init(property, &tag, &sequence);
    if (result != 0) {
        return result;
    }
    if (tag != SEP_DER_TAG_SEQUENCE) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    sep_der_decoded_info_t key = {0};
    result = sep_der_decode_sequence_next(&sequence, &key);
    if (result != 0) {
        return result;
    }
    if (key.tag != SEP_DER_TAG_IA5_STRING) {
        return SEP_DER_UNEXPECTED_TAG;
    }
    const sep_der_item_t key_item = key.content;
    sep_u32 fourcc = 0;
    result = sep_der_parse_integer(&key.content, &fourcc);
    if (result != 0) {
        return result;
    }
    if ((SEP_DER_TAG_PRIVATE_CONSTRUCTED | fourcc) != expected_tag) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    sep_der_decoded_info_t value = {0};
    result = sep_der_decode_sequence_next(&sequence, &value);
    if (result != 0) {
        return result;
    }
    if (sep_der_decode_sequence_next(&sequence, &key) !=
        SEP_DER_END_OF_SEQUENCE) {
        return SEP_DER_UNEXPECTED_TAG;
    }
    if (sequence.end != property->data + property->length) {
        return SEP_DER_BUFFER_OVERFLOW;
    }
    output[0].item = key_item;
    output[0].tag = 0;
    output[1].item = value.content;
    output[1].tag = value.tag;
    return SEP_DER_SUCCESS;
}

static int img4_typed_property(
    const sep_der_item_t *property,
    sep_u64 property_tag,
    sep_u64 value_tag,
    sep_der_item_t *value
) {
    if (property == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    sep_img4_der_element_t decoded[2] = {0};
    const int result = sep_img4_decode_property(
        property,
        SEP_DER_TAG_PRIVATE_CONSTRUCTED | property_tag,
        decoded
    );
    if (result != 0) {
        return result;
    }
    if (decoded[1].tag != value_tag) {
        return SEP_DER_UNEXPECTED_TAG;
    }
    *value = decoded[1].item;
    return SEP_DER_SUCCESS;
}

int sep_img4_decode_get_property_data(
    const sep_der_item_t *property,
    sep_u64 property_tag,
    const sep_u8 **data,
    sep_u32 *length
) {
    if (data == NULL || length == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    sep_der_item_t value = {0};
    int result = img4_typed_property(
        property,
        property_tag,
        SEP_DER_TAG_OCTET_STRING,
        &value
    );
    if (result == 0 && value.length > UINT32_MAX) {
        result = SEP_DER_BUFFER_OVERFLOW;
    }
    if (result != 0) {
        *data = NULL;
        *length = 0;
        return result;
    }
    *data = value.data;
    *length = (sep_u32)value.length;
    return 0;
}

int sep_img4_decode_get_property_integer64(
    const sep_der_item_t *property,
    sep_u64 property_tag,
    sep_u64 *value
) {
    sep_der_item_t integer = {0};
    int result = img4_typed_property(
        property,
        property_tag,
        SEP_DER_TAG_INTEGER,
        &integer
    );
    if (result == 0) {
        if (value == NULL) {
            return SEP_DER_INVALID_ARGUMENT;
        }
        result = sep_der_parse_integer64(&integer, value);
    }
    if (result != 0 && value != NULL) {
        *value = 0;
    }
    return result;
}

int sep_img4_decode_get_property_boolean(
    const sep_der_item_t *manifest,
    sep_u32 property_tag,
    sep_bool *value
) {
    sep_der_item_t boolean = {0};
    int result = img4_typed_property(
        manifest,
        property_tag,
        1,
        &boolean
    );
    if (result == 0) {
        if (value == NULL) {
            return SEP_DER_INVALID_ARGUMENT;
        }
        result = sep_der_parse_boolean(&boolean, value);
    }
    return result;
}

sep_u64 sep_img4_require_property_integer64(
    const sep_der_item_t *property,
    sep_u64 property_tag
) {
    sep_u64 value = 0;
    if (sep_img4_decode_get_property_integer64(
            property,
            property_tag,
            &value
        ) != 0) {
        sep_panic_with_reason_and_pc(0xb1, 0);
    }
    return value;
}

sep_bool sep_img4_manifest_require_boolean_property(
    const sep_der_item_t *manifest,
    sep_u32 property_tag
) {
    sep_bool value = 0;
    if (sep_img4_decode_get_property_boolean(
            manifest,
            property_tag,
            &value
        ) != 0) {
        sep_panic_with_reason_and_pc(0xaa, 0);
    }
    if (value >= 2) {
        sep_panic_reason_27();
    }
    return value & 1U;
}

int sep_img4_decode_evaluate_dictionary_properties(
    const sep_der_item_t *dictionary,
    sep_u32 dictionary_kind,
    sep_img4_property_callback_t property_callback,
    void *callback_context
) {
    if (property_callback == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    sep_der_sequence_t sequence = {0};
    int result = sep_der_decode_sequence_content_init(dictionary, &sequence);
    if (result != 0) {
        return result;
    }
    for (;;) {
        sep_der_decoded_info_t property = {0};
        result = sep_der_decode_sequence_next(&sequence, &property);
        if (result == SEP_DER_END_OF_SEQUENCE) {
            return SEP_DER_SUCCESS;
        }
        if (result != 0) {
            return result;
        }
        sep_img4_der_element_t decoded[2] = {0};
        result = sep_img4_decode_property(
            &property.content,
            property.tag,
            decoded
        );
        if (result != 0) {
            return result;
        }
        const sep_u64 allowed_types =
            (UINT64_C(1) << 1) | (UINT64_C(1) << 2) |
            (UINT64_C(1) << 4) | (UINT64_C(1) << 22);
        if (decoded[1].tag > 22 ||
            (allowed_types & (UINT64_C(1) << decoded[1].tag)) == 0 ||
            (property.tag & SEP_DER_TAG_PRIVATE_CONSTRUCTED) !=
                SEP_DER_TAG_PRIVATE_CONSTRUCTED ||
            property.content.length > UINT32_MAX) {
            return decoded[1].tag > 22
                ? SEP_DER_UNEXPECTED_TAG
                : SEP_DER_BUFFER_OVERFLOW;
        }
        sep_der_item_t callback_property = {
            property.content.data,
            (sep_u32)property.content.length,
        };
        result = property_callback(
            property.tag,
            &callback_property,
            dictionary_kind,
            callback_context
        );
        if (result != 0) {
            return result;
        }
    }
}

static int img4_evaluate_certificate_dictionary(
    const sep_der_item_t *requirements,
    const sep_der_item_t *actual
) {
    sep_der_sequence_t sequence = {0};
    int result = sep_der_decode_sequence_content_init(requirements, &sequence);
    if (result != 0) {
        return result;
    }
    for (;;) {
        sep_der_decoded_info_t requirement = {0};
        result = sep_der_decode_sequence_next(&sequence, &requirement);
        if (result == SEP_DER_END_OF_SEQUENCE) {
            return 0;
        }
        if (result != 0) {
            return -1;
        }
        sep_img4_der_element_t decoded[2] = {0};
        result = sep_img4_decode_property(
            &requirement.content,
            requirement.tag,
            decoded
        );
        if (result != 0) {
            return result;
        }
        sep_der_item_t actual_value = {0};
        const int found = sep_der_img4_decode_content_find_item_with_tag(
            actual,
            requirement.tag,
            &actual_value
        );
        if (decoded[1].tag == 1 || decoded[1].tag == 2 ||
            decoded[1].tag == 4) {
            if (found != 0 ||
                actual_value.length != requirement.content.length ||
                sep_constant_time_memcmp_veneer(
                    actual_value.data,
                    requirement.content.data,
                    actual_value.length
                ) != 0) {
                return -1;
            }
        } else if (decoded[1].tag == SEP_DER_TAG_CONTEXT_CONSTRUCTED_0) {
            if (found != 0) {
                return found;
            }
        } else if (decoded[1].tag == SEP_DER_TAG_CONTEXT_CONSTRUCTED_1) {
            if (found != SEP_DER_END_OF_SEQUENCE) {
                return SEP_DER_UNEXPECTED_TAG;
            }
        } else {
            return SEP_DER_UNEXPECTED_TAG;
        }
    }
}

int sep_img4_decode_evaluate_certificate_properties_internal(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *non_manifest_properties
) {
    if (image == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    if (image->manifest.embedded_image.data == NULL) {
        return SEP_DER_DECODE_ERROR;
    }
    sep_u64 tag = 0;
    sep_der_sequence_t sequence = {0};
    int result = sep_der_decode_sequence_init(
        &image->manifest.embedded_image,
        &tag,
        &sequence
    );
    if (result != 0) {
        return result;
    }
    if (tag != SEP_DER_TAG_SET) {
        return SEP_DER_UNEXPECTED_TAG;
    }
    for (;;) {
        sep_der_decoded_info_t encoded = {0};
        result = sep_der_decode_sequence_next(&sequence, &encoded);
        if (result == SEP_DER_END_OF_SEQUENCE) {
            return 0;
        }
        if (result != 0) {
            return -1;
        }
        const sep_der_item_t *actual;
        if (encoded.tag ==
            (SEP_DER_TAG_PRIVATE_CONSTRUCTED | MANP_MAGIC)) {
            actual = &image->manifest_properties;
        } else if (encoded.tag ==
            (SEP_DER_TAG_PRIVATE_CONSTRUCTED | MANX_MAGIC)) {
            if (non_manifest_properties != NULL) {
                *non_manifest_properties = encoded.content;
            }
            continue;
        } else if (encoded.tag ==
            (SEP_DER_TAG_PRIVATE_CONSTRUCTED | OBJP_MAGIC)) {
            actual = &image->object_properties;
            if (actual->data == NULL && actual->length == 0) {
                continue;
            }
        } else {
            return SEP_DER_UNEXPECTED_TAG;
        }
        sep_img4_der_element_t decoded[2] = {0};
        result = sep_img4_decode_property(
            &encoded.content,
            encoded.tag,
            decoded
        );
        if (result != 0) {
            return result;
        }
        if (decoded[1].tag != SEP_DER_TAG_SET) {
            return SEP_DER_UNEXPECTED_TAG;
        }
        result = img4_evaluate_certificate_dictionary(
            &decoded[1].item,
            actual
        );
        if (result != 0) {
            return result;
        }
    }
}

int sep_img4_decode_evaluate_certificate_properties(
    const sep_img4_decode_context_t *image
) {
    return sep_img4_decode_evaluate_certificate_properties_internal(
        image,
        NULL
    );
}
