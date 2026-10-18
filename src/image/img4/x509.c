#include "open_secure_rom/x509.h"

static const sep_u8 img4_manifest_extension_oid[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0f,
};

static sep_bool is_img4_manifest_extension(const sep_der_item_t *oid) {
    if (oid->length != sizeof(img4_manifest_extension_oid)) {
        return 0;
    }
    sep_u8 difference = 0;
    for (sep_size_t index = 0;
         index < sizeof(img4_manifest_extension_oid);
         ++index) {
        difference |= oid->data[index] ^ img4_manifest_extension_oid[index];
    }
    return difference == 0;
}

static int parse_extension(
    const sep_der_item_t *content,
    sep_der_item_t *oid,
    sep_der_item_t *value
) {
    sep_der_sequence_t sequence;
    sep_der_decoded_info_t decoded;
    if (sep_der_decode_sequence_content_init(content, &sequence) != 0) {
        return -1;
    }
    if (sep_der_decode_sequence_next(&sequence, &decoded) != 0 ||
        decoded.tag != 6) {
        return -1;
    }
    *oid = decoded.content;

    if (sep_der_decode_sequence_next(&sequence, &decoded) != 0) {
        return -1;
    }
    if (decoded.tag == 1) {
        if (sep_der_decode_sequence_next(&sequence, &decoded) != 0) {
            return -1;
        }
    }
    if (decoded.tag != SEP_DER_TAG_OCTET_STRING) {
        return -1;
    }
    *value = decoded.content;

    return sep_der_decode_sequence_next(&sequence, &decoded) ==
        SEP_DER_END_OF_SEQUENCE ? 0 : -1;
}

int sep_x509_find_img4_certificate_extension(
    const sep_x509_certificate_t *certificate,
    sep_der_item_t *extension_value
) {
    extension_value->data = 0;
    extension_value->length = 0;
    const sep_der_item_t *extensions = &certificate->fields[9];
    if (extensions->length == 0) {
        return 0;
    }

    sep_u64 tag;
    sep_der_sequence_t sequence;
    if (sep_der_decode_sequence_init(extensions, &tag, &sequence) != 0 ||
        tag != SEP_DER_TAG_SEQUENCE) {
        return -1;
    }

    sep_bool saw_extension = 0;
    sep_der_decoded_info_t decoded;
    int status;
    while ((status = sep_der_decode_sequence_next(&sequence, &decoded)) == 0) {
        if (decoded.tag != SEP_DER_TAG_SEQUENCE) {
            return -1;
        }

        sep_der_item_t oid;
        sep_der_item_t value;
        if (parse_extension(&decoded.content, &oid, &value) != 0) {
            return -1;
        }
        saw_extension = 1;
        if (!is_img4_manifest_extension(&oid)) {
            continue;
        }

        sep_der_decoded_info_t extension;
        if (sep_der_decode_item(&value, &extension) != 0 ||
            extension.tag != SEP_DER_TAG_SET) {
            return -1;
        }
        *extension_value = value;
    }

    return status == SEP_DER_END_OF_SEQUENCE && saw_extension ? 0 : -1;
}
