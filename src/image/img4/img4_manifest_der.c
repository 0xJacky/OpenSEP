#include "open_secure_rom/der.h"

enum {
    IM4M_MAGIC = 0x494d344dU,
    IM4C_MAGIC = 0x494d3443U,
    MANB_MAGIC = 0x4d414e42U,
    MANP_MAGIC = 0x4d414e50U,
};

static const sep_der_item_spec_t img4_manifest_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_INTEGER, 0},
    {32, SEP_DER_TAG_SET, SEP_DER_SAVE_ENCODING},
    {48, SEP_DER_TAG_OCTET_STRING, 0},
    {64, SEP_DER_TAG_SEQUENCE, 0},
};

static const sep_der_item_spec_t img4_certificate_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_INTEGER, 0},
    {32, SEP_DER_TAG_SET, SEP_DER_SAVE_ENCODING},
    {48, SEP_DER_TAG_OCTET_STRING, 0},
};

static const sep_der_item_spec_t img4_unsigned_common_specs[] = {
    {0, SEP_DER_TAG_IA5_STRING, 0},
    {16, SEP_DER_TAG_INTEGER, 0},
    {32, SEP_DER_TAG_SET, SEP_DER_SAVE_ENCODING},
};

int sep_der_img4_decode_manifest_common(
    const sep_der_item_t *encoded,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    sep_der_img4_manifest_t *decoded,
    sep_u32 magic
) {
    if (encoded == 0 || decoded == 0) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    if (encoded->data == 0 || encoded->length == 0) {
        return SEP_DER_SUCCESS;
    }

    int result = sep_der_parse_sequence_to_object(
        encoded,
        item_count,
        specs,
        decoded,
        sizeof(*decoded),
        0
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (sep_der_img4_decode_tag_compare(&decoded->magic, magic) != 0) {
        return SEP_DER_UNEXPECTED_TAG;
    }

    sep_u32 version = 0;
    result = sep_der_parse_integer(&decoded->version, &version);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    return version <= 2 ? SEP_DER_SUCCESS : SEP_DER_UNEXPECTED_TAG;
}

int sep_der_img4_decode_manifest(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
) {
    return sep_der_img4_decode_manifest_common(
        encoded,
        5,
        img4_manifest_specs,
        decoded,
        IM4M_MAGIC
    );
}

int sep_der_img4_decode_unsigned_manifest(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
) {
    return sep_der_img4_decode_manifest_common(
        encoded,
        3,
        img4_unsigned_common_specs,
        decoded,
        IM4M_MAGIC
    );
}

int sep_der_img4_decode_certificate(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
) {
    return sep_der_img4_decode_manifest_common(
        encoded,
        4,
        img4_certificate_specs,
        decoded,
        IM4C_MAGIC
    );
}

int sep_der_img4_decode_unsigned_certificate(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
) {
    return sep_der_img4_decode_manifest_common(
        encoded,
        3,
        img4_unsigned_common_specs,
        decoded,
        IM4C_MAGIC
    );
}

int sep_der_img4_decode_parse_manifest_properties(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *object_dictionary,
    sep_der_item_t *manifest_properties
) {
    return sep_der_img4_decode_parse_manifest_properties_internal(
        image,
        object_dictionary,
        manifest_properties,
        MANB_MAGIC
    );
}

int sep_der_img4_decode_parse_manifest_properties_internal(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *object_dictionary,
    sep_der_item_t *manifest_properties,
    sep_u32 object_type
) {
    if (image == 0 ||
        (object_dictionary == 0 && manifest_properties == 0)) {
        return SEP_DER_INVALID_ARGUMENT;
    }

    sep_der_decoded_info_t properties = {0};
    int result = sep_der_decode_item(&image->manifest.properties, &properties);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (properties.tag != SEP_DER_TAG_SET) {
        return -1;
    }

    sep_u32 version = 0;
    result = sep_der_parse_integer(&image->manifest.version, &version);
    if (result != SEP_DER_SUCCESS) {
        return result;
    }

    sep_img4_der_element_t object[2] = {0};
    /* Version 2 moved the object dictionary from SET to SEQUENCE. */
    const sep_u64 object_value_tag = version == 2
        ? SEP_DER_TAG_SEQUENCE
        : SEP_DER_TAG_SET;
    result = sep_der_img4_decode_find_property(
        &properties.content,
        SEP_DER_TAG_PRIVATE_CONSTRUCTED | object_type,
        object_value_tag,
        object
    );
    if (result != SEP_DER_SUCCESS) {
        return result;
    }
    if (object_dictionary != 0) {
        *object_dictionary = object[1].item;
    }

    sep_img4_der_element_t manifest[2] = {0};
    result = sep_der_img4_decode_find_property(
        &object[1].item,
        SEP_DER_TAG_PRIVATE_CONSTRUCTED | MANP_MAGIC,
        SEP_DER_TAG_SET,
        manifest
    );
    if (result == SEP_DER_SUCCESS && manifest_properties != 0) {
        *manifest_properties = manifest[1].item;
    }
    return result;
}
