#include "open_secure_rom/img4.h"

#include "open_secure_rom/bignum.h"
#include "open_secure_rom/crypto_fault.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/rsa.h"
#include "open_secure_rom/runtime.h"

enum {
    IM4M_MAGIC = 0x494d344dU,
    IM4C_MAGIC = 0x494d3443U,
};

/*
 * The canary the RSA verifier returns on success (see rsa.c).  A value of the
 * ROM's interface, as observed in AVPSEPBooter.
 */
static const sep_u8 img4_rsa_canary[16] = {
    0xea, 0xc5, 0x4a, 0x7c, 0x9f, 0x28, 0xdf, 0x10,
    0xb6, 0xe9, 0x3e, 0xb9, 0x1c, 0xd3, 0x3a, 0xc5,
};

static sep_bool img4_secondary_root_selected;
static sep_u8 img4_primary_root_canary[16];
static sep_u8 img4_secondary_root_canary[16];

static void img4_high_zero(void *destination, sep_size_t length) {
    sep_u8 *bytes = destination;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

static void img4_high_copy(
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

static int img4_digest_arguments(
    void *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
) {
    if (digest == NULL || digest_length == 0 || trust_callbacks == NULL ||
        trust_callbacks->digest == NULL || trust_callbacks->algorithm == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    if (digest_length > 48 ||
        trust_callbacks->algorithm->digest_size > 48) {
        return SEP_DER_BUFFER_OVERFLOW;
    }
    return SEP_DER_SUCCESS;
}

sep_bool sep_img4_root_key_canaries_are_valid(
    sep_bool include_secondary_root
) {
    if (sep_constant_time_compare_checked(
            16,
            img4_primary_root_canary,
            img4_rsa_canary
        ) != 0) {
        return 0;
    }
    if (!include_secondary_root) {
        return 1;
    }
    return sep_constant_time_compare_checked(
        16,
        img4_secondary_root_canary,
        img4_rsa_canary
    ) == 0;
}

int sep_img4_runtime_digest(
    const void *data,
    sep_size_t data_length,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_runtime_callback_context_t *context
) {
    if (data == NULL || data_length == 0 || digest == NULL ||
        context == NULL || context->algorithm == NULL ||
        digest_length != context->algorithm->digest_size ||
        context->algorithm->digest_descriptor == NULL ||
        *context->algorithm->digest_descriptor == NULL ||
        (*context->algorithm->digest_descriptor)->output_size !=
            digest_length) {
        return -1;
    }
    sep_ccdigest(
        *context->algorithm->digest_descriptor,
        data_length,
        data,
        digest
    );
    return 0;
}

int sep_img4_verify_rsa_signature_and_pin_root(
    const sep_der_item_t *public_key,
    const sep_u8 *digest_algorithm_oid,
    const sep_der_item_t *signature,
    const sep_der_item_t *digest
) {
    if (public_key == NULL || signature == NULL || digest == NULL ||
        ((uintptr_t)public_key & 7U) != 0 ||
        ((uintptr_t)signature & 7U) != 0 ||
        ((uintptr_t)digest & 7U) != 0) {
        sep_panic_reason_1a();
    }

    union {
        sep_u64 alignment;
        sep_u8 bytes[SEP_CCRSA_PUB_CONTEXT_SIZE(64)];
    } first_storage, second_storage;
    img4_high_zero(&first_storage, sizeof(first_storage));
    img4_high_zero(&second_storage, sizeof(second_storage));
    sep_ccrsa_pub_ctx_t *first = (sep_ccrsa_pub_ctx_t *)first_storage.bytes;
    sep_ccrsa_pub_ctx_t *second = (sep_ccrsa_pub_ctx_t *)second_storage.bytes;
    first->modulus_field.n = 64;
    second->modulus_field.n = 64;

    if (sep_rsa_public_key_decode_pkcs1(
            first,
            (sep_u32)public_key->length,
            public_key->data
        ) != 0) {
        return -1;
    }
    sep_u8 *canary = img4_secondary_root_selected
        ? img4_secondary_root_canary
        : img4_primary_root_canary;
    if (sep_rsa_verify_pkcs1v15_digest_checked(
            first,
            digest_algorithm_oid,
            digest->length,
            digest->data,
            signature->length,
            signature->data,
            canary
        ) != 0) {
        return -1;
    }
    if (sep_rsa_public_key_decode_pkcs1(
            second,
            (sep_u32)public_key->length,
            public_key->data
        ) != 0 ||
        sep_constant_time_compare_checked(
            0x200,
            first_storage.bytes,
            second_storage.bytes
        ) != 0 ||
        !sep_img4_root_key_canaries_are_valid(img4_secondary_root_selected)) {
        return -1;
    }
    img4_secondary_root_selected = 1;
    return 0;
}

int sep_img4_runtime_verify_signature_rsa(
    const sep_u8 *public_key,
    sep_size_t public_key_length,
    const sep_u8 *digest,
    sep_size_t digest_length,
    const sep_u8 *signature,
    sep_size_t signature_length,
    const sep_img4_runtime_callback_context_t *context
) {
    if (public_key == NULL || public_key_length == 0 || digest == NULL ||
        digest_length == 0 || signature == NULL || signature_length == 0 ||
        context == NULL || ((uintptr_t)context & 7U) != 0 ||
        context->algorithm == NULL ||
        ((uintptr_t)context->algorithm & 7U) != 0 ||
        context->algorithm->digest_descriptor == NULL ||
        ((uintptr_t)context->algorithm->digest_descriptor & 7U) != 0 ||
        *context->algorithm->digest_descriptor == NULL ||
        (*context->algorithm->digest_descriptor)->output_size !=
            digest_length) {
        return -1;
    }
    const sep_der_item_t public_key_item = {
        public_key,
        (sep_u32)public_key_length,
    };
    const sep_der_item_t signature_item = {
        signature,
        (sep_u32)signature_length,
    };
    const sep_der_item_t digest_item = {
        digest,
        (sep_u32)digest_length,
    };
    return sep_img4_verify_rsa_signature_and_pin_root(
        &public_key_item,
        context->algorithm->digest_oid,
        &signature_item,
        &digest_item
    );
}

int sep_img4_decode_init(
    const sep_u8 *data,
    sep_size_t length,
    sep_img4_decode_context_t *image
) {
    if (data == NULL || image == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    img4_high_zero(image, sizeof(*image));
    const sep_der_item_t encoded = {data, length};
    sep_der_img4_decoded_t decoded = {0};
    int result = sep_der_img4_decode(&encoded, &decoded);
    if (result == 0) {
        result = sep_der_img4_decode_payload(&decoded.payload, &image->payload);
    }
    if (result == 0) {
        result = sep_der_img4_decode_manifest(
            &decoded.manifest,
            &image->manifest
        );
    }
    if (result == 0) {
        result = sep_der_img4_decode_restore_info(
            &decoded.restore_info,
            &image->restore_info
        );
    }
    if (result == 0) {
        image->payload_raw = decoded.payload;
        image->manifest_raw = decoded.manifest;
    }
    return result;
}

int sep_img4_decode_init_manifest_common(
    const sep_u8 *data,
    sep_size_t length,
    sep_bool signed_object,
    sep_img4_decode_context_t *image,
    sep_u32 magic
) {
    if (data == NULL || image == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    img4_high_zero(image, sizeof(*image));
    const sep_der_item_t encoded = {data, length};
    int result;
    if (magic == IM4C_MAGIC) {
        result = signed_object
            ? sep_der_img4_decode_certificate(&encoded, &image->manifest)
            : sep_der_img4_decode_unsigned_certificate(
                &encoded,
                &image->manifest
            );
    } else if (magic == IM4M_MAGIC) {
        result = signed_object
            ? sep_der_img4_decode_manifest(&encoded, &image->manifest)
            : sep_der_img4_decode_unsigned_manifest(&encoded, &image->manifest);
    } else {
        return SEP_DER_UNEXPECTED_TAG;
    }
    if (result != 0) {
        return result;
    }
    if (image->manifest.properties.data == NULL) {
        return SEP_DER_DECODE_ERROR;
    }
    sep_der_decoded_info_t decoded = {0};
    result = sep_der_decode_item(&encoded, &decoded);
    if (result != 0) {
        return result;
    }
    image->manifest_raw.data = data;
    image->manifest_raw.length = (sep_size_t)(
        decoded.content.data + decoded.content.length - data
    );
    return image->manifest_raw.length == length
        ? SEP_DER_SUCCESS
        : SEP_DER_BUFFER_OVERFLOW;
}

int sep_img4_decode_init_manifest(
    const sep_u8 *data,
    sep_size_t length,
    sep_img4_decode_context_t *image
) {
    return sep_img4_decode_init_manifest_common(
        data,
        length,
        1,
        image,
        IM4M_MAGIC
    );
}

int sep_img4_decode_get_payload(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *payload
) {
    if (image == NULL || payload == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    if (image->payload.payload.data == NULL ||
        image->payload.payload.length == 0) {
        *payload = (sep_der_item_t){0};
        return SEP_DER_END_OF_SEQUENCE;
    }
    *payload = image->payload.payload;
    return SEP_DER_SUCCESS;
}

int sep_img4_decode_get_payload_keybag(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *keybag
) {
    if (image == NULL || keybag == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    if (image->payload.payload.data == NULL ||
        image->payload.payload.length == 0) {
        *keybag = (sep_der_item_t){0};
        return SEP_DER_END_OF_SEQUENCE;
    }
    *keybag = image->payload.keybag;
    return SEP_DER_SUCCESS;
}

int sep_img4_decode_manifest_exists(
    const sep_img4_decode_context_t *image,
    sep_bool *exists
) {
    if (image == NULL || exists == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    *exists = image->manifest_raw.data != NULL;
    return SEP_DER_SUCCESS;
}

int sep_img4_decode_restore_info_exists(
    const sep_img4_decode_context_t *image,
    sep_bool *exists
) {
    if (image == NULL || exists == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    *exists = image->restore_info.nonce.data != NULL &&
        image->restore_info.nonce.length != 0;
    return SEP_DER_SUCCESS;
}

int sep_img4_decode_get_manifest(
    const sep_img4_decode_context_t *image,
    const sep_u8 **data,
    sep_u32 *length
) {
    if (image == NULL || data == NULL || length == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    if (image->manifest_raw.length > UINT32_MAX) {
        return SEP_DER_BUFFER_OVERFLOW;
    }
    *data = image->manifest_raw.data;
    *length = (sep_u32)image->manifest_raw.length;
    return *data == NULL || *length == 0 ? -1 : 0;
}

static int img4_decode_payload_properties_item(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *properties
) {
    if (image->payload_raw.data == NULL) {
        return SEP_DER_END_OF_SEQUENCE;
    }
    union {
        sep_u64 alignment;
        sep_u8 bytes[160];
    } decoded;
    img4_high_zero(&decoded, sizeof(decoded));
    const int result = sep_der_img4_decode_payload_with_properties(
        &image->payload_raw,
        (sep_der_img4_payload_t *)decoded.bytes
    );
    if (result != 0) {
        return result;
    }
    *properties = *(const sep_der_item_t *)(decoded.bytes + 96);
    return properties->data == NULL
        ? SEP_DER_END_OF_SEQUENCE
        : SEP_DER_SUCCESS;
}

int sep_img4_decode_payload_properties_exists(
    const sep_img4_decode_context_t *image,
    sep_bool *exists
) {
    if (image == NULL || exists == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    sep_der_item_t properties = {0};
    const int result = img4_decode_payload_properties_item(image, &properties);
    *exists = result == SEP_DER_SUCCESS;
    return result == SEP_DER_END_OF_SEQUENCE ? SEP_DER_SUCCESS : result;
}

int sep_img4_decode_get_payload_properties(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *properties
) {
    if (image == NULL || properties == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    *properties = (sep_der_item_t){0};
    return img4_decode_payload_properties_item(image, properties);
}

int sep_img4_decode_copy_payload_digest(
    const sep_img4_decode_context_t *image,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
) {
    if (image == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    int result = img4_digest_arguments(
        digest,
        digest_length,
        trust_callbacks
    );
    if (result != 0) {
        return result;
    }
    if (image->payload.payload.data == NULL ||
        image->payload.payload.length == 0) {
        return SEP_DER_END_OF_SEQUENCE;
    }
    if (image->payload_hash_valid) {
        img4_high_copy(digest, image->payload.payload_hash, digest_length);
        return 0;
    }
    sep_u8 computed[48] = {0};
    result = trust_callbacks->digest(
        image->payload_raw.data,
        image->payload_raw.length,
        computed,
        digest_length,
        trust_callbacks
    );
    if (result == 0) {
        img4_high_copy(digest, computed, trust_callbacks->algorithm->digest_size);
    }
    return result;
}

int sep_img4_decode_copy_manifest_digest(
    const sep_img4_decode_context_t *image,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
) {
    if (image == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    int result = img4_digest_arguments(
        digest,
        digest_length,
        trust_callbacks
    );
    if (result != 0) {
        return result;
    }
    if (image->manifest_raw.data == NULL) {
        return SEP_DER_END_OF_SEQUENCE;
    }
    if (image->manifest_hash_valid) {
        img4_high_copy(digest, image->manifest.full_hash, digest_length);
        return 0;
    }
    sep_u8 computed[48] = {0};
    result = trust_callbacks->digest(
        image->manifest_raw.data,
        image->manifest_raw.length,
        computed,
        digest_length,
        trust_callbacks
    );
    if (result == 0) {
        img4_high_copy(digest, computed, digest_length);
    }
    return result;
}

int sep_img4_decode_copy_payload_properties_digest(
    const sep_der_item_t *payload_properties,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
) {
    if (payload_properties == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    int result = img4_digest_arguments(
        digest,
        digest_length,
        trust_callbacks
    );
    if (result != 0) {
        return result;
    }
    sep_u8 computed[48] = {0};
    result = trust_callbacks->digest(
        payload_properties->data,
        payload_properties->length,
        computed,
        digest_length,
        trust_callbacks
    );
    if (result == 0) {
        img4_high_copy(digest, computed, digest_length);
    }
    return result;
}
