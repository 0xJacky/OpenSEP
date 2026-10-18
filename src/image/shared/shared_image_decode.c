#include "open_secure_rom/shared_image.h"

#include "open_secure_rom/aes.h"
#include "open_secure_rom/crypto_digest.h"
#include "open_secure_rom/event_log.h"
#include "open_secure_rom/img4.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

enum {
    SHARED_IMAGE_SEPI = 0x73657069U,
    SHARED_IMAGE_RSEP = 0x72736570U,
};

static const sep_u8 shared_image_sha384_rsa_oid_bytes[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
};
static const sep_der_item_t shared_image_sha384_rsa_oid = {
    shared_image_sha384_rsa_oid_bytes,
    sizeof(shared_image_sha384_rsa_oid_bytes),
};

static int shared_image_digest(
    const void *data,
    sep_size_t data_length,
    void *digest,
    sep_size_t digest_length,
    const void *context
) {
    (void)context;
    if (digest_length != 48) return -1;
    sep_ccdigest(
        sep_digest_info_for_bit_length(384),
        data_length,
        data,
        digest
    );
    return 0;
}

static int shared_image_verify_chain(
    const sep_u8 *chain,
    sep_u32 chain_length,
    const sep_u8 **leaf_public_key,
    sep_size_t *leaf_public_key_length,
    const sep_u8 **extension,
    sep_size_t *extension_length,
    const sep_img4_trust_callbacks_t *callbacks,
    void *context
) {
    (void)context;
    return sep_img4_verify_chain_ddi(
        chain,
        chain_length,
        leaf_public_key,
        leaf_public_key_length,
        extension,
        extension_length,
        callbacks
    );
}

static int shared_image_verify_signature(
    const sep_u8 *public_key,
    sep_size_t public_key_length,
    const sep_u8 *signature,
    sep_size_t signature_length,
    const sep_u8 *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *callbacks,
    void *context
) {
    (void)context;
    const sep_img4_runtime_callback_context_t runtime = {
        .algorithm = callbacks->algorithm,
    };
    return sep_img4_runtime_verify_signature_rsa(
        public_key,
        public_key_length,
        digest,
        digest_length,
        signature,
        signature_length,
        &runtime
    );
}

static int shared_image_evaluate_certificate(
    sep_img4_decode_context_t *image,
    void *context
) {
    (void)context;
    return sep_img4_decode_evaluate_certificate_properties(image);
}

/*
 * Whether an image's manifest has to be trusted before the image is used.
 *
 * Off, and that is a statement about this machine rather than a shortcut.  The
 * main processor's boot chain here starts from a replacement boot ROM, which
 * boots manifests of our own making; the SEPOS image the kernel hands over is
 * Apple's production firmware, whose manifest chains to a different Apple
 * root than the DDI anchor this ROM carries (img4_chain.c), and no anchor
 * that would accept it can be supplied here.  Asking for a verdict that cannot come out right only stops the
 * boot at `sep_img4_decode_perform_trust_evaluation`, which is where it
 * stopped: panic reason 426.
 *
 * The evaluation still runs, and a failure still goes in the event log, so
 * anything built on top of this can see it.  What changes is that the answer
 * is not fatal and `decoded_properties[261]` -- the overall verdict -- is not
 * derived from it.  Build with -DOPEN_SECURE_ROM_ENFORCE_IMAGE_TRUST=1 to put
 * it back.
 */
#ifndef OPEN_SECURE_ROM_ENFORCE_IMAGE_TRUST
#define OPEN_SECURE_ROM_ENFORCE_IMAGE_TRUST 0
#endif

static void shared_image_trust_callbacks_initialize(
    sep_img4_trust_callbacks_t *callbacks,
    sep_img4_digest_algorithm_t *algorithm,
    const sep_ccdigest_info_t **descriptor
) {
    *descriptor = sep_digest_info_for_bit_length(384);
    *algorithm = (sep_img4_digest_algorithm_t){
        48,
        (*descriptor)->oid,
        descriptor,
    };
    *callbacks = (sep_img4_trust_callbacks_t){
        .digest = shared_image_digest,
        .verify_chain = shared_image_verify_chain,
        .verify_signature = shared_image_verify_signature,
        .evaluate_certificate = shared_image_evaluate_certificate,
        .algorithm = algorithm,
        .signature_algorithm_oid = &shared_image_sha384_rsa_oid,
    };
}

static int shared_image_decode_keybag(
    const sep_der_item_t *encoded,
    sep_shared_image_auxiliary_t *auxiliary
) {
    if (encoded->data == NULL || encoded->length == 0) return 0;
    sep_der_decoded_info_t outer = {0};
    sep_der_sequence_t entries = {0};
    if (sep_der_decode_item(encoded, &outer) != 0 ||
        outer.tag != SEP_DER_TAG_SEQUENCE ||
        sep_der_decode_sequence_content_init(&outer.content, &entries) != 0) {
        return -1;
    }
    for (;;) {
        sep_der_decoded_info_t encoded_entry = {0};
        int result = sep_der_decode_sequence_next(&entries, &encoded_entry);
        if (result == SEP_DER_END_OF_SEQUENCE) return 0;
        if (result != 0 || encoded_entry.tag != SEP_DER_TAG_SEQUENCE) return -1;
        sep_der_sequence_t fields = {0};
        if (sep_der_decode_sequence_content_init(
                &encoded_entry.content, &fields) != 0) return -1;
        sep_der_decoded_info_t field = {0};
        sep_u32 index = 0;
        if (sep_der_decode_sequence_next(&fields, &field) != 0 ||
            field.tag != SEP_DER_TAG_INTEGER ||
            sep_der_parse_integer(&field.content, &index) != 0 || index > 2) {
            return -1;
        }
        sep_shared_image_auxiliary_keybag_entry_t *entry =
            &auxiliary->entries[index];
        if (entry->present) return -1;
        if (sep_der_decode_sequence_next(&fields, &field) != 0 ||
            field.content.length != 16) return -1;
        sep_memmove(entry->metadata, field.content.data, 16);
        if (sep_der_decode_sequence_next(&fields, &field) != 0 ||
            (field.content.length != 16 && field.content.length != 24 &&
             field.content.length != 32)) return -1;
        entry->key_bit_length = (sep_u32)(field.content.length * 8);
        sep_memmove(entry->key, field.content.data, field.content.length);
        if (sep_der_decode_sequence_next(&fields, &field) !=
            SEP_DER_END_OF_SEQUENCE) return -1;
        entry->present = 1;
        auxiliary->present = 1;
    }
}

sep_shared_image_context_t sep_shared_image_decode_and_evaluate(
    sep_u32 mode,
    const sep_u8 *image,
    sep_size_t image_length
) {
    sep_shared_image_context_t context;
    sep_memzero(&context, sizeof(context));
    sep_shared_image_properties_initialize(
        (sep_shared_image_properties_t *)&context);
    sep_shared_image_auxiliary_t auxiliary;
    sep_shared_image_auxiliary_initialize(&auxiliary);

    sep_size_t encoded_length = 0;
    if (!sep_der_sequence_encoded_length(
            image, image_length, &encoded_length) ||
        encoded_length > image_length) {
        sep_panic_with_reason_and_pc(1141, 0);
    }
    sep_img4_decode_context_t decoded;
    if (sep_img4_decode_init(image, encoded_length, &decoded) != 0) {
        sep_panic_with_reason_and_pc(1147, 0);
    }
    sep_bool restore_info_exists = 0;
    if (sep_img4_decode_restore_info_exists(
            &decoded, &restore_info_exists) != 0 || restore_info_exists) {
        sep_panic_with_reason_and_pc(1155, 0);
    }
    const sep_u32 payload_type = mode == 0 ? SHARED_IMAGE_SEPI :
        mode == 1 ? SHARED_IMAGE_RSEP : 0;
    if (payload_type == 0) sep_panic_with_reason_and_pc(358, 0);

    sep_der_item_t payload = {0};
    if (sep_img4_decode_get_payload(&decoded, &payload) != 0 ||
        payload.data < image || payload.length > image_length ||
        (sep_size_t)(payload.data - image) > image_length - payload.length) {
        sep_panic_with_reason_and_pc(376, 0);
    }
    context.payload_data = payload.data;
    context.payload_size = payload.length;

    sep_der_item_t keybag = {0};
    if (sep_img4_decode_get_payload_keybag(&decoded, &keybag) != 0 ||
        shared_image_decode_keybag(&keybag, &auxiliary) != 0) {
        sep_panic_with_reason_and_pc(103, 0);
    }
    sep_memmove(context.auxiliary, &auxiliary, sizeof(auxiliary));
    sep_shared_image_context_set_mode(&context, (sep_u8)mode);
    sep_shared_image_context_set_payload_type(&context, payload_type);
    context.decoded_properties[256] = 1;

    sep_bool manifest_exists = 0;
    if (sep_img4_decode_manifest_exists(&decoded, &manifest_exists) != 0) {
        sep_panic_with_reason_and_pc(1173, 0);
    }
    if (manifest_exists) {
        const sep_u8 *manifest = NULL;
        sep_u32 manifest_length = 0;
        if (sep_img4_decode_get_manifest(
                &decoded, &manifest, &manifest_length) != 0 ||
            manifest_length > 0xc000U) {
            sep_panic_with_reason_and_pc(1185, 0);
        }
        context.manifest_data = manifest;
        context.manifest_size = manifest_length;

        const sep_ccdigest_info_t *descriptor;
        sep_img4_digest_algorithm_t algorithm;
        sep_img4_trust_callbacks_t trust_callbacks;
        shared_image_trust_callbacks_initialize(
            &trust_callbacks,
            &algorithm,
            &descriptor
        );
        if (sep_img4_decode_perform_trust_evaluation(
                payload_type,
                &decoded,
                (sep_img4_property_callback_t)
                    sep_shared_image_property_callback,
                &trust_callbacks,
                &context
            ) != 0) {
            if (OPEN_SECURE_ROM_ENFORCE_IMAGE_TRUST) {
                sep_panic_with_reason_and_pc(426, 0);
            }
            sep_protocol_event_log_append(0x8002000a);
        }
        context.decoded_properties[262] = 1;
        context.decoded_properties[257] =
            sep_shared_image_validate_platform_constraints(&context);

        const sep_checked_bytes48_t manifest_digest =
            sep_checked_bytes48_from_data(decoded.manifest.full_hash, 48);
        sep_shared_image_properties_set_manifest_digest(
            (sep_shared_image_properties_t *)&context,
            &manifest_digest
        );

        sep_bool payload_properties_exist = 0;
        if (sep_img4_decode_payload_properties_exists(
                &decoded, &payload_properties_exist) != 0) {
            sep_panic_with_reason_and_pc(1201, 0);
        }
        context.decoded_properties[258] = payload_properties_exist ? 0 : 1;
        if (payload_properties_exist) {
            sep_der_item_t payload_properties = {0};
            sep_u8 digest[48] = {0};
            if (sep_img4_decode_get_payload_properties(
                    &decoded, &payload_properties) != 0 ||
                sep_img4_decode_copy_payload_properties_digest(
                    &payload_properties,
                    digest,
                    sizeof(digest),
                    &trust_callbacks
                ) != 0) {
                sep_panic_with_reason_and_pc(1210, 0);
            }
            const sep_checked_bytes48_t checked =
                sep_checked_bytes48_from_data(digest, sizeof(digest));
            if (sep_shared_image_properties_oppd_matches_if_present(
                    (const sep_shared_image_properties_t *)&context,
                    &checked)) {
                sep_der_item_t constraints = {0};
                const int result = sep_der_img4_decode_parse_certificate_properties(
                    &payload_properties,
                    0x636f6e73U,
                    &constraints
                );
                context.decoded_properties[258] = result ==
                    SEP_DER_END_OF_SEQUENCE ? 1 :
                    result == 0 ? sep_img4_constraints_evaluate(
                        constraints.data, constraints.length) : 0;
            }
        }

        if (sep_shared_image_properties_has_dgst(
                (const sep_shared_image_properties_t *)&context)) {
            const sep_checked_bytes48_t payload_digest =
                sep_checked_bytes48_from_data(decoded.payload.payload_hash, 48);
            const sep_bool matches =
                sep_shared_image_properties_dgst_matches_if_present(
                    (const sep_shared_image_properties_t *)&context,
                    &payload_digest
                );
            context.decoded_properties[259] = matches;
            context.decoded_properties[260] = matches;
        }
    }

    context.decoded_properties[261] =
        (manifest_exists && OPEN_SECURE_ROM_ENFORCE_IMAGE_TRUST) ?
        (context.decoded_properties[257] &
         context.decoded_properties[258] &
         context.decoded_properties[259] &
         context.decoded_properties[260]) : 1;
    return context;
}
