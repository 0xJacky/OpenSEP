#ifndef OPEN_SECURE_ROM_IMG4_H
#define OPEN_SECURE_ROM_IMG4_H

#include "open_secure_rom/crypto_digest.h"
#include "open_secure_rom/der.h"

typedef struct sep_x509_certificate {
    sep_der_item_t fields[10];
} sep_x509_certificate_t;

struct sep_img4_trust_callbacks;

typedef int (*sep_img4_property_callback_t)(
    sep_u64 property_tag,
    sep_der_item_t *property,
    sep_u32 dictionary_kind,
    void *context
);

typedef int (*sep_img4_digest_callback_t)(
    const void *data,
    sep_size_t data_length,
    void *digest,
    sep_size_t digest_length,
    const void *context
);
typedef int (*sep_img4_chain_callback_t)(
    const sep_u8 *chain,
    sep_u32 chain_length,
    const sep_u8 **leaf_public_key,
    sep_size_t *leaf_public_key_length,
    const sep_u8 **extension,
    sep_size_t *extension_length,
    const struct sep_img4_trust_callbacks *callbacks,
    void *context
);
typedef int (*sep_img4_signature_callback_t)(
    const sep_u8 *public_key,
    sep_size_t public_key_length,
    const sep_u8 *signature,
    sep_size_t signature_length,
    const sep_u8 *digest,
    sep_size_t digest_length,
    const struct sep_img4_trust_callbacks *callbacks,
    void *context
);
typedef int (*sep_img4_certificate_callback_t)(
    sep_img4_decode_context_t *image,
    void *context
);

typedef struct sep_img4_digest_algorithm {
    sep_size_t digest_size;
    const sep_u8 *digest_oid;
    const sep_ccdigest_info_t *const *digest_descriptor;
} sep_img4_digest_algorithm_t;

typedef struct sep_img4_trust_callbacks {
    sep_img4_digest_callback_t digest;
    sep_img4_chain_callback_t verify_chain;
    sep_img4_signature_callback_t verify_signature;
    sep_img4_certificate_callback_t evaluate_certificate;
    const sep_img4_digest_algorithm_t *algorithm;
    const sep_der_item_t *signature_algorithm_oid;
} sep_img4_trust_callbacks_t;

typedef const void *(*sep_img4_manifest_digest_callback_t)(
    sep_img4_decode_context_t *image,
    void *context
);
typedef int (*sep_img4_find_property_callback_t)(
    const sep_der_item_t *dictionary,
    sep_u64 expected_tag,
    sep_u64 value_tag,
    sep_img4_der_element_t output[2],
    void *context
);

typedef struct sep_img4_property_callbacks {
    sep_img4_property_callback_t evaluate;
    sep_img4_manifest_digest_callback_t manifest_digest;
    sep_img4_find_property_callback_t find_property;
} sep_img4_property_callbacks_t;

typedef struct sep_img4_runtime_callback_context {
    const void *reserved[4];
    const sep_img4_digest_algorithm_t *algorithm;
} sep_img4_runtime_callback_context_t;

typedef struct sep_img4_constraint_record {
    sep_u8 value_source;
    sep_u8 comparison;
    sep_u8 reserved0[6];
    sep_u64 value_address;
    sep_u64 mask;
    sep_u64 reserved1;
} sep_img4_constraint_record_t;

typedef int (*sep_img4_crack_chain_callback_t)(
    const sep_der_item_t *encoded_chain,
    sep_der_item_t *certificate_chain,
    sep_u32 certificate_count
);

sep_bool sep_img4_root_key_canaries_are_valid(sep_bool include_secondary_root);
int sep_img4_runtime_verify_signature_rsa(
    const sep_u8 *public_key,
    sep_size_t public_key_length,
    const sep_u8 *digest,
    sep_size_t digest_length,
    const sep_u8 *signature,
    sep_size_t signature_length,
    const sep_img4_runtime_callback_context_t *context
);
int sep_img4_verify_rsa_signature_and_pin_root(
    const sep_der_item_t *public_key,
    const sep_u8 *digest_algorithm_oid,
    const sep_der_item_t *signature,
    const sep_der_item_t *digest
);
sep_u64 sep_img4_require_property_integer64(
    const sep_der_item_t *property,
    sep_u64 property_tag
);
sep_bool sep_img4_manifest_require_boolean_property(
    const sep_der_item_t *manifest,
    sep_u32 property_tag
);
sep_bool sep_img4_constraints_evaluate(
    const sep_u8 *records,
    sep_size_t records_length
);
void sep_img4_constraint_record_decode(
    sep_img4_constraint_record_t *decoded,
    const sep_u8 raw_record[24]
);
void sep_img4_constraint_record_decode_checked(
    sep_img4_constraint_record_t *decoded,
    const sep_u8 raw_record[24]
);
sep_bool sep_img4_constraint_record_evaluate(
    const sep_img4_constraint_record_t *record
);
int sep_img4_decode_property(
    const sep_der_item_t *property,
    sep_u64 expected_tag,
    sep_img4_der_element_t output[2]
);
int sep_img4_decode_get_payload(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *payload
);
int sep_img4_decode_get_payload_keybag(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *keybag
);
int sep_img4_decode_manifest_exists(
    const sep_img4_decode_context_t *image,
    sep_bool *exists
);
int sep_img4_decode_restore_info_exists(
    const sep_img4_decode_context_t *image,
    sep_bool *exists
);
int sep_img4_decode_get_property_data(
    const sep_der_item_t *property,
    sep_u64 property_tag,
    const sep_u8 **data,
    sep_u32 *length
);
int sep_img4_decode_evaluate_certificate_properties(
    const sep_img4_decode_context_t *image
);
int sep_img4_decode_init(
    const sep_u8 *data,
    sep_size_t length,
    sep_img4_decode_context_t *image
);
int sep_img4_decode_init_manifest(
    const sep_u8 *data,
    sep_size_t length,
    sep_img4_decode_context_t *image
);
int sep_img4_decode_init_manifest_common(
    const sep_u8 *data,
    sep_size_t length,
    sep_bool signed_object,
    sep_img4_decode_context_t *image,
    sep_u32 magic
);
int sep_img4_decode_perform_trust_evaluation(
    sep_u32 object_type,
    sep_img4_decode_context_t *image,
    sep_img4_property_callback_t property_callback,
    const sep_img4_trust_callbacks_t *trust_callbacks,
    void *callback_context
);
int sep_img4_parse_certificate_chain(
    const sep_der_item_t *certificate_chain,
    sep_u32 certificate_count,
    sep_der_item_t *signed_certificates,
    sep_x509_certificate_t *certificates,
    sep_der_item_t *public_keys,
    sep_der_item_t *extensions
);
int sep_img4_verify_chain_signatures(
    const sep_der_item_t *issuer_public_key,
    const sep_der_item_t *signed_certificate,
    const sep_img4_trust_callbacks_t *trust_callbacks
);
int sep_img4_verify_chain_with_crack_callback(
    const sep_u8 *chain,
    sep_u32 chain_length,
    const sep_u8 **leaf_public_key,
    sep_size_t *leaf_public_key_length,
    const sep_u8 **extension,
    sep_size_t *extension_length,
    const sep_img4_trust_callbacks_t *trust_callbacks,
    sep_img4_crack_chain_callback_t crack_chain
);
int sep_img4_verify_chain_ddi(
    const sep_u8 *chain,
    sep_u32 chain_length,
    const sep_u8 **leaf_public_key,
    sep_size_t *leaf_public_key_length,
    const sep_u8 **extension,
    sep_size_t *extension_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
);
int sep_img4_crack_chain_rsa4k_sha384_ddi(
    const sep_der_item_t *encoded_chain,
    sep_der_item_t *certificate_chain,
    sep_u32 certificate_count
);
int sep_img4_crack_chain_with_anchor(
    const sep_der_item_t *encoded_chain,
    sep_der_item_t *certificate_chain,
    sep_u32 certificate_count
);
int sep_img4_decode_copy_payload_digest(
    const sep_img4_decode_context_t *image,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
);
int sep_img4_decode_copy_manifest_digest(
    const sep_img4_decode_context_t *image,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
);
int sep_img4_decode_get_manifest(
    const sep_img4_decode_context_t *image,
    const sep_u8 **data,
    sep_u32 *length
);
int sep_img4_decode_payload_properties_exists(
    const sep_img4_decode_context_t *image,
    sep_bool *exists
);
int sep_img4_decode_get_payload_properties(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *properties
);
int sep_img4_decode_copy_payload_properties_digest(
    const sep_der_item_t *payload_properties,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_trust_callbacks_t *trust_callbacks
);
int sep_img4_decode_get_property_integer64(
    const sep_der_item_t *property,
    sep_u64 property_tag,
    sep_u64 *value
);
int sep_img4_decode_get_property_boolean(
    const sep_der_item_t *manifest,
    sep_u32 property_tag,
    sep_bool *value
);
int sep_img4_decode_evaluate_certificate_properties_internal(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *non_manifest_properties
);
int sep_img4_decode_evaluate_dictionary_properties(
    const sep_der_item_t *dictionary,
    sep_u32 dictionary_kind,
    sep_img4_property_callback_t property_callback,
    void *callback_context
);
int sep_img4_decode_perform_trust_evaluation_with_callbacks_internal(
    sep_u32 object_type,
    sep_img4_decode_context_t *image,
    const sep_img4_property_callbacks_t *property_callbacks,
    const sep_img4_trust_callbacks_t *trust_callbacks,
    sep_bool manifest_only,
    void *callback_context
);
int sep_img4_runtime_digest(
    const void *data,
    sep_size_t data_length,
    void *digest,
    sep_size_t digest_length,
    const sep_img4_runtime_callback_context_t *context
);

#endif
