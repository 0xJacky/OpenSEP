#include "open_secure_rom/img4.h"

#include "open_secure_rom/runtime.h"

int sep_img4_decode_perform_trust_evaluation(
    sep_u32 object_type,
    sep_img4_decode_context_t *image,
    sep_img4_property_callback_t property_callback,
    const sep_img4_trust_callbacks_t *trust_callbacks,
    void *callback_context
) {
    const sep_img4_property_callbacks_t callbacks = {
        .evaluate = property_callback,
        .manifest_digest = NULL,
        .find_property = NULL,
    };
    return sep_img4_decode_perform_trust_evaluation_with_callbacks_internal(
        object_type,
        image,
        &callbacks,
        trust_callbacks,
        0,
        callback_context
    );
}

int sep_img4_decode_perform_trust_evaluation_with_callbacks_internal(
    sep_u32 object_type,
    sep_img4_decode_context_t *image,
    const sep_img4_property_callbacks_t *property_callbacks,
    const sep_img4_trust_callbacks_t *trust_callbacks,
    sep_bool manifest_only,
    void *callback_context
) {
    if (image == NULL || property_callbacks == NULL ||
        trust_callbacks == NULL || property_callbacks->evaluate == NULL ||
        trust_callbacks->digest == NULL ||
        trust_callbacks->verify_chain == NULL ||
        trust_callbacks->verify_signature == NULL ||
        trust_callbacks->evaluate_certificate == NULL ||
        trust_callbacks->algorithm == NULL ||
        image->manifest_raw.data == NULL) {
        return SEP_DER_INVALID_ARGUMENT;
    }
    const sep_size_t digest_size = trust_callbacks->algorithm->digest_size;
    if (digest_size > 48) {
        return SEP_DER_BUFFER_OVERFLOW;
    }

    int result = trust_callbacks->digest(
        image->manifest_raw.data,
        image->manifest_raw.length,
        image->manifest.full_hash,
        digest_size,
        trust_callbacks
    );
    if (result != 0) {
        return result;
    }
    image->manifest_hash_valid = 1;

    sep_bool verified_manifest = 0;
    const void *cached_digest = property_callbacks->manifest_digest == NULL
        ? NULL
        : property_callbacks->manifest_digest(image, callback_context);
    if (cached_digest != NULL && sep_constant_time_memcmp_veneer(
            image->manifest.full_hash,
            cached_digest,
            digest_size
        ) == 0) {
        verified_manifest = 1;
    }

    if (!verified_manifest) {
        const sep_u8 *leaf_public_key = NULL;
        sep_size_t leaf_public_key_length = 0;
        const sep_u8 *extension = NULL;
        sep_size_t extension_length = 0;
        result = trust_callbacks->verify_chain(
            image->manifest.certificates.data,
            (sep_u32)image->manifest.certificates.length,
            &leaf_public_key,
            &leaf_public_key_length,
            &extension,
            &extension_length,
            trust_callbacks,
            callback_context
        );
        if (result != 0) {
            return result;
        }
        image->manifest.embedded_image = (sep_der_item_t){
            extension,
            extension_length,
        };
        result = trust_callbacks->digest(
            image->manifest.properties.data,
            image->manifest.properties.length,
            image->manifest.properties_hash,
            digest_size,
            trust_callbacks
        );
        if (result != 0) {
            return result;
        }
        result = trust_callbacks->verify_signature(
            leaf_public_key,
            leaf_public_key_length,
            image->manifest.signature.data,
            image->manifest.signature.length,
            image->manifest.properties_hash,
            digest_size,
            trust_callbacks,
            callback_context
        );
        if (result != 0) {
            return result;
        }
    }

    result = sep_der_img4_decode_parse_manifest_properties(
        image,
        &image->manifest_body,
        &image->manifest_properties
    );
    if (result != 0) {
        return result;
    }

    if (!manifest_only) {
        sep_img4_der_element_t property[2] = {0};
        const sep_u64 expected_tag = SEP_DER_TAG_PRIVATE_CONSTRUCTED |
            object_type;
        result = property_callbacks->find_property == NULL
            ? sep_der_img4_decode_find_property(
                &image->manifest_body,
                expected_tag,
                SEP_DER_TAG_SET,
                property
            )
            : property_callbacks->find_property(
                &image->manifest_body,
                expected_tag,
                SEP_DER_TAG_SET,
                property,
                callback_context
            );
        if (result != 0) {
            return result;
        }
        image->object_properties = property[1].item;
    }

    if (!verified_manifest) {
        result = trust_callbacks->evaluate_certificate(
            image,
            callback_context
        );
        if (result != 0) {
            return result;
        }
    }

    if (image->payload.payload.data != NULL &&
        image->payload.payload.length != 0) {
        result = trust_callbacks->digest(
            image->payload_raw.data,
            image->payload_raw.length,
            image->payload.payload_hash,
            digest_size,
            trust_callbacks
        );
        if (result != 0) {
            return result;
        }
        image->payload_hash_valid = 1;
    }

    result = sep_img4_decode_evaluate_dictionary_properties(
        &image->manifest_properties,
        0,
        property_callbacks->evaluate,
        callback_context
    );
    if (result != 0 || manifest_only) {
        return result;
    }
    return sep_img4_decode_evaluate_dictionary_properties(
        &image->object_properties,
        1,
        property_callbacks->evaluate,
        callback_context
    );
}
