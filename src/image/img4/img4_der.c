#include "open_secure_rom/der.h"

#include <stdint.h>

_Static_assert(sizeof(sep_der_img4_decoded_t) == 64, "IMG4 envelope ABI");
_Static_assert(
    sizeof(sep_der_img4_payload_compression_t) == 32,
    "IMG4 compression ABI"
);
_Static_assert(
    sizeof(sep_der_img4_payload_properties_t) == 32,
    "IMG4 payload properties ABI"
);
_Static_assert(sizeof(sep_der_img4_payload_t) == 144, "IMG4 payload ABI");
_Static_assert(sizeof(sep_der_img4_manifest_t) == 192, "IMG4 manifest ABI");
_Static_assert(
    sizeof(sep_der_img4_restore_info_t) == 32,
    "IMG4 restore info ABI"
);
_Static_assert(sizeof(sep_img4_decode_context_t) == 456, "IMG4 context ABI");
_Static_assert(
    __builtin_offsetof(sep_img4_decode_context_t, payload) == 88,
    "IMG4 payload context offset"
);
_Static_assert(
    __builtin_offsetof(sep_img4_decode_context_t, manifest) == 232,
    "IMG4 manifest context offset"
);
_Static_assert(
    __builtin_offsetof(sep_img4_decode_context_t, restore_info) == 424,
    "IMG4 restore-info context offset"
);

enum {
    IMG4_MAGIC = 0x494d4734U,
    IM4P_MAGIC = 0x494d3450U,
    IM4R_MAGIC = 0x494d3452U,
    PAYP_MAGIC = 0x50415950U,
};

static const sep_der_item_spec_t img4_top_level_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_SEQUENCE, SEP_DER_SAVE_ENCODING},
    {32, SEP_DER_TAG_CONTEXT_CONSTRUCTED_0, SEP_DER_OPTIONAL},
    {48, SEP_DER_TAG_CONTEXT_CONSTRUCTED_1, SEP_DER_OPTIONAL},
};

static const sep_der_item_spec_t img4_payload_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_IA5_STRING, 0},
    {32, SEP_DER_TAG_IA5_STRING, 0},
    {48, SEP_DER_TAG_OCTET_STRING, 0},
    {64, SEP_DER_TAG_OCTET_STRING, SEP_DER_OPTIONAL},
    {80, SEP_DER_TAG_SEQUENCE, SEP_DER_OPTIONAL},
};

static const sep_der_item_spec_t img4_payload_with_properties_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_IA5_STRING, 0},
    {32, SEP_DER_TAG_IA5_STRING, 0},
    {48, SEP_DER_TAG_OCTET_STRING, 0},
    {64, SEP_DER_TAG_OCTET_STRING, SEP_DER_OPTIONAL},
    {80, SEP_DER_TAG_SEQUENCE, SEP_DER_OPTIONAL},
    {96, SEP_DER_TAG_CONTEXT_CONSTRUCTED_0, SEP_DER_OPTIONAL},
};

static const sep_der_item_spec_t img4_restore_info_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_SET, 0},
};

static const sep_der_item_spec_t img4_payload_properties_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_SET, 0},
};

static const sep_der_item_spec_t img4_payload_compression_specs[] = {
    {0, SEP_DER_TAG_INTEGER, 0},
    {16, SEP_DER_TAG_INTEGER, 0},
};

static void img4_zero(void *destination, sep_size_t length) {
    sep_u8 *bytes = destination;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

static void img4_copy(
    void *destination,
    const void *source,
    sep_size_t length
) {
    sep_u8 *output = destination;
    const sep_u8 *input = source;
    for (sep_size_t index = 0; index < length; ++index) {
        output[index] = input[index];
    }
}

int sep_der_img4_decode(
    const sep_der_item_t *encoded,
    sep_der_img4_decoded_t *decoded
) {
    if (encoded == 0 || decoded == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    sep_der_decoded_info_t envelope = {0};
    int result = sep_der_decode_item(encoded, &envelope);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (envelope.tag != SEP_DER_TAG_SEQUENCE) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    const uintptr_t encoded_address = (uintptr_t)encoded->data;
    const uintptr_t content_address = (uintptr_t)envelope.content.data;
    if (encoded->length > UINTPTR_MAX - encoded_address ||
        envelope.content.length > UINTPTR_MAX - content_address) {
        return SEP_DER_BUFFER_OVERFLOW;
    }
    /* IMG4 accepts exactly one envelope, so trailing bytes fail as overflow. */
    if (encoded_address + encoded->length !=
        content_address + envelope.content.length) {
        return SEP_DER_BUFFER_OVERFLOW;
    }

    result = sep_der_parse_sequence_content_to_object(
        &envelope.content,
        4,
        img4_top_level_specs,
        decoded,
        sizeof(*decoded),
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    return sep_der_img4_decode_tag_compare(&decoded->magic, IMG4_MAGIC) == 0
        ? SEP_DER_SUCCESS
        : SEP_DER_UNEXPECTED_TAG;
}

int sep_der_img4_decode_payload_compression(
    const sep_der_item_t *compression,
    sep_der_img4_payload_compression_t *decoded
) {
    if (compression == 0 || decoded == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    int result = sep_der_parse_sequence_content_to_object(
        compression,
        2,
        img4_payload_compression_specs,
        decoded,
        sizeof(*decoded),
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    sep_u32 algorithm = 2;
    result = sep_der_parse_integer(&decoded->algorithm, &algorithm);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    return algorithm <= 1 ? SEP_DER_SUCCESS : SEP_DER_INVALID_ARGUMENT;
}

int sep_der_img4_decode_payload_with_properties(
    const sep_der_item_t *payload,
    sep_der_img4_payload_t *decoded
) {
    if (payload == 0 || decoded == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    int result = sep_der_parse_sequence_to_object(
        payload,
        7,
        img4_payload_with_properties_specs,
        decoded,
        160,
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (sep_der_img4_decode_tag_compare(&decoded->magic, IM4P_MAGIC) != 0) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    if (decoded->compression.data != 0) {
        sep_der_img4_payload_compression_t compression = {0};
        result = sep_der_img4_decode_payload_compression(
            &decoded->compression,
            &compression
        );
        if (result != SEP_DER_SUCCESS) {
            return result;
        }
    }

    /* The optional properties item occupies the payload hash scratch prefix. */
    const sep_der_item_t *properties = (const sep_der_item_t *)(
        (const sep_u8 *)decoded + 96
    );
    if (properties->data != 0) {
        sep_der_img4_payload_properties_t parsed_properties = {0};
        result = sep_der_img4_decode_payload_properties(
            properties,
            &parsed_properties
        );
    }
    return result;
}

int sep_der_img4_decode_payload_properties(
    const sep_der_item_t *properties,
    sep_der_img4_payload_properties_t *decoded
) {
    if (properties == 0) {
        return SEP_DER_SUCCESS;
    }
    if (decoded == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    img4_zero(decoded, sizeof(*decoded));
    if (properties->data == 0 || properties->length == 0) {
        return SEP_DER_SUCCESS;
    }

    const int result = sep_der_parse_sequence_to_object(
        properties,
        2,
        img4_payload_properties_specs,
        decoded,
        sizeof(*decoded),
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    return sep_der_img4_decode_tag_compare(&decoded->magic, PAYP_MAGIC) == 0
        ? SEP_DER_SUCCESS
        : SEP_DER_UNEXPECTED_TAG;
}

int sep_der_img4_decode_payload(
    const sep_der_item_t *payload,
    sep_der_img4_payload_t *decoded
) {
    if (payload == 0 || decoded == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    sep_u8 with_properties[160];
    img4_zero(with_properties, sizeof(with_properties));
    int result = sep_der_img4_decode_payload_with_properties(
        payload,
        (sep_der_img4_payload_t *)with_properties
    );
    if (result == SEP_DER_SUCCESS) {
        /* Persistent payload state ends before the temporary properties item. */
        img4_copy(decoded, with_properties, 96);
        return SEP_DER_SUCCESS;
    }

    result = sep_der_parse_sequence_to_object(
        payload,
        6,
        img4_payload_specs,
        decoded,
        sizeof(*decoded),
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (sep_der_img4_decode_tag_compare(&decoded->magic, IM4P_MAGIC) != 0) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    if (decoded->compression.data != 0) {
        sep_der_img4_payload_compression_t compression = {0};
        result = sep_der_img4_decode_payload_compression(
            &decoded->compression,
            &compression
        );
        if (result != SEP_DER_SUCCESS) {
            return result;
        }
    }
    return SEP_DER_SUCCESS;
}

int sep_der_img4_decode_restore_info(
    const sep_der_item_t *encoded,
    sep_der_img4_restore_info_t *decoded
) {
    if (encoded == 0) {
        return SEP_DER_SUCCESS;
    }
    if (decoded == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    img4_zero(decoded, sizeof(*decoded));
    if (encoded->data == 0 || encoded->length == 0) {
        return SEP_DER_SUCCESS;
    }

    const int result = sep_der_parse_sequence_to_object(
        encoded,
        2,
        img4_restore_info_specs,
        decoded,
        sizeof(*decoded),
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    return sep_der_img4_decode_tag_compare(&decoded->magic, IM4R_MAGIC) == 0
        ? SEP_DER_SUCCESS
        : SEP_DER_UNEXPECTED_TAG;
}

int sep_der_img4_decode_parse_certificate_properties(
    const sep_der_item_t *certificate,
    sep_u32 property_tag,
    sep_der_item_t *value
) {
    if (certificate == 0 || value == 0 || certificate->data == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    sep_der_item_t payload_sequence = {0};
    int result = sep_der_img4_decode_content_find_item_with_tag(
        certificate,
        SEP_DER_TAG_SEQUENCE,
        &payload_sequence
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (payload_sequence.data == 0) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    sep_der_item_t magic = {0};
    result = sep_der_img4_decode_content_find_item_with_tag(
        &payload_sequence,
        SEP_DER_TAG_IA5_STRING,
        &magic
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (sep_der_img4_decode_tag_compare(&magic, PAYP_MAGIC) != 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    sep_der_item_t properties = {0};
    result = sep_der_img4_decode_content_find_item_with_tag(
        &payload_sequence,
        SEP_DER_TAG_SET,
        &properties
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    sep_der_sequence_t sequence = {0};
    result = sep_der_decode_sequence_content_init(&properties, &sequence);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    for (;;) {
        sep_der_decoded_info_t encoded_property = {0};
        result = sep_der_decode_sequence_next(&sequence, &encoded_property);
        if (result != SEP_DER_SUCCESS) {
            return result;
        }

        sep_der_decoded_info_t property = {0};
        /* Non-property certificate extension entries remain skippable. */
        if (sep_der_decode_item(&encoded_property.content, &property) !=
            SEP_DER_SUCCESS) {
            continue;
        }

        result = sep_der_img4_decode_content_find_item_with_tag(
            &property.content,
            SEP_DER_TAG_IA5_STRING,
            &magic
        );
        if (result != SEP_DER_SUCCESS) {
            return result;
        }
        if (sep_der_img4_decode_tag_compare(&magic, property_tag) != 0) {
            continue;
        }

        sep_der_sequence_t property_sequence = {0};
        if (sep_der_decode_sequence_content_init(
                &property.content,
                &property_sequence
            ) != SEP_DER_SUCCESS) {
            continue;
        }

        sep_der_decoded_info_t key = {0};
        if (sep_der_decode_sequence_next(&property_sequence, &key) !=
                SEP_DER_SUCCESS ||
            key.tag != SEP_DER_TAG_IA5_STRING) {
            continue;
        }

        sep_der_decoded_info_t property_value = {0};
        if (sep_der_decode_sequence_next(
                &property_sequence,
                &property_value
            ) != SEP_DER_SUCCESS) {
            continue;
        }
        if (property_value.content.data == 0) {
            return SEP_DER_UNEXPECTED_TAG;
        }
        *value = property_value.content;
        return SEP_DER_SUCCESS;
    }
}
