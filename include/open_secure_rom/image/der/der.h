#ifndef OPEN_SECURE_ROM_DER_H
#define OPEN_SECURE_ROM_DER_H

#include "open_secure_rom/types.h"

typedef struct sep_der_item {
    const sep_u8 *data;
    sep_size_t length;
} sep_der_item_t;

typedef struct sep_der_decoded_info {
    sep_u64 tag;
    sep_der_item_t content;
} sep_der_decoded_info_t;

typedef struct sep_der_sequence {
    const sep_u8 *next_item;
    const sep_u8 *end;
} sep_der_sequence_t;

typedef struct sep_der_item_spec {
    sep_size_t offset;
    sep_u64 tag;
    sep_u16 options;
} sep_der_item_spec_t;

typedef struct sep_img4_der_element {
    sep_der_item_t item;
    sep_u64 tag;
} sep_img4_der_element_t;

typedef struct sep_der_img4_decoded {
    sep_der_item_t magic;
    sep_der_item_t payload;
    sep_der_item_t manifest;
    sep_der_item_t restore_info;
} sep_der_img4_decoded_t;

typedef struct sep_der_img4_payload_compression {
    sep_der_item_t algorithm;
    sep_der_item_t uncompressed_size;
} sep_der_img4_payload_compression_t;

typedef struct sep_der_img4_payload_properties {
    sep_der_item_t magic;
    sep_der_item_t properties;
} sep_der_img4_payload_properties_t;

typedef struct sep_der_img4_payload {
    sep_der_item_t magic;
    sep_der_item_t type;
    sep_der_item_t version;
    sep_der_item_t payload;
    sep_der_item_t keybag;
    sep_der_item_t compression;
    sep_u8 payload_hash[48];
} sep_der_img4_payload_t;

typedef struct sep_der_img4_manifest {
    sep_der_item_t magic;
    sep_der_item_t version;
    sep_der_item_t properties;
    sep_der_item_t signature;
    sep_der_item_t certificates;
    sep_der_item_t embedded_image;
    sep_u8 full_hash[48];
    sep_u8 properties_hash[48];
} sep_der_img4_manifest_t;

typedef struct sep_der_img4_restore_info {
    sep_der_item_t magic;
    sep_der_item_t nonce;
} sep_der_img4_restore_info_t;

typedef struct sep_img4_decode_context {
    sep_bool payload_hash_valid;
    sep_bool manifest_hash_valid;
    sep_u8 reserved[6];
    sep_der_item_t payload_raw;
    sep_der_item_t manifest_raw;
    sep_der_item_t manifest_body;
    sep_der_item_t manifest_properties;
    sep_der_item_t object_properties;
    sep_der_img4_payload_t payload;
    sep_der_img4_manifest_t manifest;
    sep_der_img4_restore_info_t restore_info;
} sep_img4_decode_context_t;

enum {
    SEP_DER_SUCCESS = 0,
    SEP_DER_END_OF_SEQUENCE = 1,
    SEP_DER_UNEXPECTED_TAG = 2,
    SEP_DER_DECODE_ERROR = 3,
    SEP_DER_INCOMPLETE_SEQUENCE = 5,
    SEP_DER_INVALID_ARGUMENT = 6,
    SEP_DER_BUFFER_OVERFLOW = 7,
};

enum {
    SEP_DER_OPTIONAL = 0x0001,
    SEP_DER_ANY_TAG = 0x0002,
    SEP_DER_SKIP = 0x0004,
    SEP_DER_SAVE_ENCODING = 0x0008,
};

enum {
    SEP_DER_TAG_INTEGER = 0x02,
    SEP_DER_TAG_OCTET_STRING = 0x04,
    SEP_DER_TAG_IA5_STRING = 0x16,
    SEP_DER_TAG_SEQUENCE = 0x2000000000000010ULL,
    SEP_DER_TAG_SET = 0x2000000000000011ULL,
    SEP_DER_TAG_CONTEXT_CONSTRUCTED_0 = 0xa000000000000000ULL,
    SEP_DER_TAG_CONTEXT_CONSTRUCTED_1 = 0xa000000000000001ULL,
    SEP_DER_TAG_PRIVATE_CONSTRUCTED = 0xe000000000000000ULL,
};

sep_bool sep_der_sequence_encoded_length(
    const sep_u8 *data,
    sep_size_t available,
    sep_size_t *encoded_length
);
int sep_der_decode_item(
    const sep_der_item_t *der,
    sep_der_decoded_info_t *decoded
);
int sep_der_decode_item_partial_buffer_get_length(
    const sep_der_item_t *der,
    sep_der_decoded_info_t *decoded,
    sep_size_t *encoded_length
);
int sep_der_decode_item_partial_buffer(
    const sep_der_item_t *der,
    sep_der_decoded_info_t *decoded,
    sep_bool allow_partial_buffer
);
int sep_der_parse_bit_string(
    const sep_der_item_t *contents,
    sep_der_item_t *bit_string_bytes,
    sep_u8 *unused_bit_count
);
int sep_der_parse_boolean(
    const sep_der_item_t *contents,
    sep_bool *value
);
int sep_der_parse_integer(
    const sep_der_item_t *contents,
    sep_u32 *value
);
int sep_der_parse_integer64(
    const sep_der_item_t *contents,
    sep_u64 *value
);
int sep_der_decode_sequence_init(
    const sep_der_item_t *der,
    sep_u64 *tag,
    sep_der_sequence_t *sequence
);
int sep_der_decode_sequence_content_init(
    const sep_der_item_t *content,
    sep_der_sequence_t *sequence
);
int sep_der_decode_sequence_next(
    sep_der_sequence_t *sequence,
    sep_der_decoded_info_t *decoded
);
int sep_der_parse_sequence_to_object(
    const sep_der_item_t *der,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    void *destination,
    sep_size_t destination_size,
    sep_size_t size_to_zero
);
int sep_der_parse_sequence_content_to_object(
    const sep_der_item_t *content,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    void *destination,
    sep_size_t destination_size,
    sep_size_t size_to_zero
);
int sep_der_parse_sequence(
    const sep_der_item_t *der,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    void *destination,
    sep_size_t size_to_zero
);
sep_bool sep_der_oid_compare(
    const sep_der_item_t *lhs,
    const sep_der_item_t *rhs
);
int sep_der_img4_decode_content_find_item_with_tag(
    const sep_der_item_t *content,
    sep_u64 tag,
    sep_der_item_t *item
);
int sep_der_img4_decode_tag_compare(
    const sep_der_item_t *item,
    sep_u32 magic
);
int sep_der_img4_decode_find_property_in_sequence(
    sep_der_sequence_t *sequence,
    sep_u64 expected_tag,
    sep_u64 value_tag,
    sep_img4_der_element_t output[2]
);
int sep_der_img4_decode_property_with_item(
    const sep_der_item_t *property,
    sep_u64 expected_tag,
    sep_u64 value_tag,
    sep_img4_der_element_t output[2]
);
int sep_der_img4_decode_find_property(
    const sep_der_item_t *content,
    sep_u64 expected_tag,
    sep_u64 value_tag,
    sep_img4_der_element_t output[2]
);
int sep_der_img4_decode(
    const sep_der_item_t *encoded,
    sep_der_img4_decoded_t *decoded
);
int sep_der_img4_decode_payload_compression(
    const sep_der_item_t *compression,
    sep_der_img4_payload_compression_t *decoded
);
int sep_der_img4_decode_payload_with_properties(
    const sep_der_item_t *payload,
    sep_der_img4_payload_t *decoded
);
int sep_der_img4_decode_payload_properties(
    const sep_der_item_t *properties,
    sep_der_img4_payload_properties_t *decoded
);
int sep_der_img4_decode_payload(
    const sep_der_item_t *payload,
    sep_der_img4_payload_t *decoded
);
int sep_der_img4_decode_manifest_common(
    const sep_der_item_t *encoded,
    sep_u16 item_count,
    const sep_der_item_spec_t *specs,
    sep_der_img4_manifest_t *decoded,
    sep_u32 magic
);
int sep_der_img4_decode_manifest(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
);
int sep_der_img4_decode_unsigned_manifest(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
);
int sep_der_img4_decode_certificate(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
);
int sep_der_img4_decode_unsigned_certificate(
    const sep_der_item_t *encoded,
    sep_der_img4_manifest_t *decoded
);
int sep_der_img4_decode_restore_info(
    const sep_der_item_t *encoded,
    sep_der_img4_restore_info_t *decoded
);
int sep_der_img4_decode_parse_manifest_properties(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *object_dictionary,
    sep_der_item_t *manifest_properties
);
int sep_der_img4_decode_parse_manifest_properties_internal(
    const sep_img4_decode_context_t *image,
    sep_der_item_t *object_dictionary,
    sep_der_item_t *manifest_properties,
    sep_u32 object_type
);
int sep_der_img4_decode_parse_certificate_properties(
    const sep_der_item_t *certificate,
    sep_u32 property_tag,
    sep_der_item_t *value
);

#endif
