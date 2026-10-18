#include "open_secure_rom/img4.h"
#include "open_secure_rom/shared_image.h"

#include <assert.h>
#include <string.h>

typedef struct test_buffer {
    sep_u8 bytes[2048];
    sep_size_t length;
} test_buffer_t;

static void append(test_buffer_t *buffer, const void *data, sep_size_t length) {
    assert(buffer->length + length <= sizeof(buffer->bytes));
    memcpy(buffer->bytes + buffer->length, data, length);
    buffer->length += length;
}

static void append_length(test_buffer_t *buffer, sep_size_t length) {
    assert(length <= 0xff);
    if (length < 0x80) {
        const sep_u8 byte = (sep_u8)length;
        append(buffer, &byte, 1);
    } else {
        const sep_u8 bytes[2] = {0x81, (sep_u8)length};
        append(buffer, bytes, sizeof(bytes));
    }
}

static test_buffer_t tlv(sep_u8 tag, const void *data, sep_size_t length) {
    test_buffer_t result = {0};
    append(&result, &tag, 1);
    append_length(&result, length);
    append(&result, data, length);
    return result;
}

static void append_buffer(test_buffer_t *output, const test_buffer_t *input) {
    append(output, input->bytes, input->length);
}

static test_buffer_t fourcc(sep_u32 value) {
    const sep_u8 bytes[4] = {
        (sep_u8)(value >> 24), (sep_u8)(value >> 16),
        (sep_u8)(value >> 8), (sep_u8)value,
    };
    return tlv(0x16, bytes, sizeof(bytes));
}

static test_buffer_t private_item(sep_u32 tag, const test_buffer_t *content) {
    sep_u8 digits[5];
    sep_size_t count = 0;
    do {
        digits[count++] = (sep_u8)(tag & 0x7fU);
        tag >>= 7;
    } while (tag != 0);
    test_buffer_t result = {0};
    const sep_u8 first = 0xff;
    append(&result, &first, 1);
    while (count != 0) {
        --count;
        const sep_u8 digit = digits[count] | (count == 0 ? 0 : 0x80U);
        append(&result, &digit, 1);
    }
    append_length(&result, content->length);
    append_buffer(&result, content);
    return result;
}

static test_buffer_t property(
    sep_u32 tag,
    sep_u8 value_tag,
    const sep_u8 *value,
    sep_size_t value_length
) {
    const test_buffer_t key = fourcc(tag);
    const test_buffer_t encoded_value = tlv(value_tag, value, value_length);
    test_buffer_t content = {0};
    append_buffer(&content, &key);
    append_buffer(&content, &encoded_value);
    const test_buffer_t sequence = tlv(0x30, content.bytes, content.length);
    return private_item(tag, &sequence);
}

static test_buffer_t keybag(void) {
    const sep_u8 index = 0;
    const sep_u8 metadata[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    const sep_u8 key[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const test_buffer_t encoded_index = tlv(0x02, &index, 1);
    const test_buffer_t encoded_metadata = tlv(0x04, metadata, sizeof(metadata));
    const test_buffer_t encoded_key = tlv(0x04, key, sizeof(key));
    test_buffer_t entry_content = {0};
    append_buffer(&entry_content, &encoded_index);
    append_buffer(&entry_content, &encoded_metadata);
    append_buffer(&entry_content, &encoded_key);
    const test_buffer_t entry = tlv(0x30, entry_content.bytes, entry_content.length);
    return tlv(0x30, entry.bytes, entry.length);
}

static test_buffer_t manifestless_img4(void) {
    const test_buffer_t magic = fourcc(0x494d4734U);
    const test_buffer_t payload_magic = fourcc(0x494d3450U);
    const test_buffer_t payload_type = fourcc(0x73657069U);
    const sep_u8 version_data[] = {'1'};
    const sep_u8 payload_data[] = {0xde, 0xad, 0xbe, 0xef};
    const test_buffer_t version = tlv(0x16, version_data, sizeof(version_data));
    const test_buffer_t payload = tlv(0x04, payload_data, sizeof(payload_data));
    const test_buffer_t encoded_keybag = keybag();
    const test_buffer_t keybag_octets = tlv(
        0x04, encoded_keybag.bytes, encoded_keybag.length);
    test_buffer_t payload_content = {0};
    append_buffer(&payload_content, &payload_magic);
    append_buffer(&payload_content, &payload_type);
    append_buffer(&payload_content, &version);
    append_buffer(&payload_content, &payload);
    append_buffer(&payload_content, &keybag_octets);
    const test_buffer_t payload_sequence = tlv(
        0x30, payload_content.bytes, payload_content.length);
    test_buffer_t envelope = {0};
    append_buffer(&envelope, &magic);
    append_buffer(&envelope, &payload_sequence);
    return tlv(0x30, envelope.bytes, envelope.length);
}

void __attribute__((noreturn)) sep_panic_with_reason_and_pc(
    sep_u32 reason,
    sep_u64 caller_pc
) {
    (void)reason;
    (void)caller_pc;
    assert(0 && "unexpected IMG4 panic");
    __builtin_unreachable();
}

void __attribute__((noreturn)) sep_panic_reason_1a(void) {
    sep_panic_with_reason_and_pc(0x1a, 0);
}

void __attribute__((noreturn)) sep_panic_reason_27(void) {
    sep_panic_with_reason_and_pc(0x27, 0);
}

void __attribute__((noreturn)) sep_panic_reason_2a(void) {
    sep_panic_with_reason_and_pc(0x2a, 0);
}

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected fatal wait");
    __builtin_unreachable();
}

void sep_protocol_diagnostic_record_write(
    sep_u32 event_code,
    const void *payload,
    sep_size_t payload_size
) {
    assert(event_code == 0x40030026);
    assert(payload != NULL && payload_size == 24);
}

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    return event_code;
}

static int digest_callback(
    const void *data,
    sep_size_t data_length,
    void *digest,
    sep_size_t digest_length,
    const void *context
) {
    (void)context;
    const sep_ccdigest_info_t *descriptor =
        sep_digest_info_for_bit_length(digest_length * 8);
    sep_ccdigest(descriptor, data_length, data, digest);
    return 0;
}

static sep_der_item_t property_content(const test_buffer_t *property_buffer) {
    const sep_der_item_t encoded = {
        property_buffer->bytes,
        property_buffer->length,
    };
    sep_der_decoded_info_t decoded = {0};
    assert(sep_der_decode_item(&encoded, &decoded) == 0);
    return decoded.content;
}

static void test_properties(void) {
    const sep_u8 integer_value[] = {0x2a};
    const sep_u8 true_value[] = {0xff};
    sep_u8 digest_value[48];
    memset(digest_value, 0xa5, sizeof(digest_value));
    const test_buffer_t integer = property(
        0x43484950U, 0x02, integer_value, sizeof(integer_value));
    const sep_der_item_t integer_item = property_content(&integer);
    sep_img4_der_element_t decoded[2] = {0};
    assert(sep_img4_decode_property(
        &integer_item, SEP_DER_TAG_PRIVATE_CONSTRUCTED | 0x43484950U,
        decoded) == 0);
    sep_u64 value = 0;
    assert(sep_img4_decode_get_property_integer64(
        &integer_item, 0x43484950U, &value) == 0 && value == 42);
    assert(sep_img4_require_property_integer64(&integer_item, 0x43484950U) == 42);

    const test_buffer_t boolean = property(
        0x454b4559U, 0x01, true_value, sizeof(true_value));
    const sep_der_item_t boolean_item = property_content(&boolean);
    sep_bool flag = 0;
    assert(sep_img4_decode_get_property_boolean(
        &boolean_item, 0x454b4559U, &flag) == 0 && flag == 1);
    assert(sep_img4_manifest_require_boolean_property(
        &boolean_item, 0x454b4559U) == 1);

    const test_buffer_t data = property(
        0x44475354U, 0x04, digest_value, sizeof(digest_value));
    sep_der_item_t data_item = property_content(&data);
    const sep_u8 *data_pointer = NULL;
    sep_u32 data_length = 0;
    assert(sep_img4_decode_get_property_data(
        &data_item, 0x44475354U, &data_pointer, &data_length) == 0);
    assert(data_length == 48 && data_pointer[0] == 0xa5);

    sep_shared_image_context_t context = {0};
    sep_shared_image_properties_initialize(
        (sep_shared_image_properties_t *)&context);
    assert(sep_shared_image_property_callback(
        SEP_DER_TAG_PRIVATE_CONSTRUCTED | 0x44475354U,
        &data_item, 1, &context) == 0);
    assert(sep_shared_image_properties_has_dgst(
        (const sep_shared_image_properties_t *)&context));
    assert(sep_shared_image_property_callback(
        SEP_DER_TAG_PRIVATE_CONSTRUCTED | 0x43484950U,
        (sep_der_item_t *)&integer_item, 0, &context) == 0);
    assert(context.decoded_properties[10] == 1);

    const sep_der_item_t dictionary = {boolean.bytes, boolean.length};
    assert(sep_img4_decode_evaluate_dictionary_properties(
        &dictionary, 1, (sep_img4_property_callback_t)
            sep_shared_image_property_callback, &context) == 0);
    assert(sep_shared_image_properties_ekey_checked(
        (const sep_shared_image_properties_t *)&context));
}

static void store_le64(sep_u8 output[8], sep_u64 value) {
    for (sep_size_t index = 0; index < 8; ++index) {
        output[index] = (sep_u8)(value >> (8 * index));
    }
}

static void test_constraints(void) {
    sep_u64 source = UINT64_C(0x1122334455667788);
    sep_u8 raw[24] = {0};
    const sep_u64 header = UINT64_C(1) << 62 |
        ((sep_u64)(uintptr_t)&source & UINT64_C(0x0fffffffffffffff));
    store_le64(raw, header);
    store_le64(raw + 8, UINT64_MAX);
    store_le64(raw + 16, source);
    sep_img4_constraint_record_t record;
    sep_img4_constraint_record_decode(&record, raw);
    assert(sep_img4_constraint_record_evaluate(&record));
    sep_img4_constraint_record_decode_checked(&record, raw);
    assert(sep_img4_constraints_evaluate(raw, sizeof(raw)));
    raw[16] ^= 1;
    assert(!sep_img4_constraints_evaluate(raw, sizeof(raw)));
}

static void test_decode_and_digest(void) {
    static const sep_u8 sha384_abc[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
    };
    const sep_ccdigest_info_t *descriptor =
        sep_digest_info_for_bit_length(384);
    const sep_img4_digest_algorithm_t algorithm = {
        48, descriptor->oid, &descriptor,
    };
    const sep_img4_runtime_callback_context_t runtime = {
        .algorithm = &algorithm,
    };
    sep_u8 digest[48] = {0};
    assert(sep_img4_runtime_digest(
        "abc", 3, digest, sizeof(digest), &runtime) == 0);
    assert(memcmp(digest, sha384_abc, sizeof(digest)) == 0);

    const test_buffer_t image = manifestless_img4();
    sep_img4_decode_context_t decoded;
    assert(sep_img4_decode_init(image.bytes, image.length, &decoded) == 0);
    sep_der_item_t payload = {0};
    sep_der_item_t keybag_item = {0};
    assert(sep_img4_decode_get_payload(&decoded, &payload) == 0);
    assert(sep_img4_decode_get_payload_keybag(&decoded, &keybag_item) == 0);
    assert(payload.length == 4 && keybag_item.length != 0);
    sep_bool exists = 1;
    assert(sep_img4_decode_manifest_exists(&decoded, &exists) == 0 && !exists);
    assert(sep_img4_decode_restore_info_exists(&decoded, &exists) == 0 && !exists);
    const sep_u8 *manifest = (const sep_u8 *)1;
    sep_u32 manifest_length = 1;
    assert(sep_img4_decode_get_manifest(
        &decoded, &manifest, &manifest_length) != 0);
    assert(sep_img4_decode_payload_properties_exists(
        &decoded, &exists) == 0 && !exists);
    sep_der_item_t properties = {0};
    assert(sep_img4_decode_get_payload_properties(
        &decoded, &properties) == SEP_DER_END_OF_SEQUENCE);

    const sep_img4_trust_callbacks_t callbacks = {
        .digest = digest_callback,
        .algorithm = &algorithm,
    };
    assert(sep_img4_decode_copy_payload_digest(
        &decoded, digest, sizeof(digest), &callbacks) == 0);
    assert(sep_img4_decode_copy_manifest_digest(
        &decoded, digest, sizeof(digest), &callbacks) == SEP_DER_END_OF_SEQUENCE);
    const sep_der_item_t abc = {(const sep_u8 *)"abc", 3};
    assert(sep_img4_decode_copy_payload_properties_digest(
        &abc, digest, sizeof(digest), &callbacks) == 0);
    assert(memcmp(digest, sha384_abc, sizeof(digest)) == 0);

    const sep_shared_image_context_t shared =
        sep_shared_image_decode_and_evaluate(0, image.bytes, image.length);
    assert(shared.payload_size == 4);
    assert(sep_shared_image_context_mode_checked(&shared) == 0);
    assert(sep_shared_image_context_payload_type_checked(&shared) == 0x73657069U);
    const sep_shared_image_auxiliary_t *auxiliary =
        (const sep_shared_image_auxiliary_t *)shared.auxiliary;
    assert(auxiliary->present && auxiliary->entries[0].present);
    const sep_shared_image_payload_keybag_t selected =
        sep_shared_image_select_payload_keybag(auxiliary);
    assert(selected.present && selected.key_bit_length == 128);
    assert(selected.key[0] == 0x10 && selected.metadata[15] == 15);
}

static int unused_property_callback(
    sep_u64 tag,
    sep_der_item_t *property_item,
    sep_u32 dictionary_kind,
    void *context
) {
    (void)tag;
    (void)property_item;
    (void)dictionary_kind;
    (void)context;
    return 0;
}

static void test_error_contracts_and_chain_anchor(void) {
    sep_img4_decode_context_t image = {0};
    const sep_img4_property_callbacks_t property_callbacks = {
        .evaluate = unused_property_callback,
    };
    const sep_img4_trust_callbacks_t trust_callbacks = {0};
    assert(sep_img4_decode_perform_trust_evaluation(
        0, &image, unused_property_callback, &trust_callbacks, NULL) ==
        SEP_DER_INVALID_ARGUMENT);
    assert(sep_img4_decode_perform_trust_evaluation_with_callbacks_internal(
        0, &image, &property_callbacks, &trust_callbacks, 0, NULL) ==
        SEP_DER_INVALID_ARGUMENT);
    assert(sep_img4_decode_evaluate_certificate_properties(&image) != 0);
    sep_der_item_t missing = {0};
    assert(sep_img4_decode_evaluate_certificate_properties_internal(
        &image, &missing) != 0);
    assert(sep_img4_decode_init_manifest(NULL, 0, &image) ==
        SEP_DER_INVALID_ARGUMENT);
    assert(sep_img4_decode_init_manifest_common(
        NULL, 0, 0, &image, 0x494d344dU) == SEP_DER_INVALID_ARGUMENT);

    const sep_u8 empty_sequence[] = {0x30, 0x00};
    const sep_der_item_t encoded = {empty_sequence, sizeof(empty_sequence)};
    sep_der_item_t chain[2] = {0};
    assert(sep_img4_crack_chain_rsa4k_sha384_ddi(
        &encoded, chain, 2) == 0);
    assert(chain[0].length == 0x572 && chain[0].data[0] == 0x30);
    memset(chain, 0, sizeof(chain));
    chain[0] = encoded;
    assert(sep_img4_crack_chain_with_anchor(&encoded, chain, 2) == 0);
    sep_der_item_t signed_certificates[6] = {0};
    sep_x509_certificate_t certificates[2] = {0};
    sep_der_item_t public_keys[2] = {0};
    sep_der_item_t extensions[2] = {0};
    assert(sep_img4_parse_certificate_chain(
        chain, 2, signed_certificates, certificates,
        public_keys, extensions) == -1);
    assert(sep_img4_verify_chain_signatures(
        &encoded, signed_certificates, &trust_callbacks) == -1);
    const sep_u8 *pointer = NULL;
    sep_size_t length = 0;
    assert(sep_img4_verify_chain_with_crack_callback(
        empty_sequence, sizeof(empty_sequence), &pointer, &length,
        NULL, NULL, &trust_callbacks, sep_img4_crack_chain_with_anchor) == -1);
    assert(sep_img4_verify_chain_ddi(
        empty_sequence, sizeof(empty_sequence), &pointer, &length,
        NULL, NULL, &trust_callbacks) == -1);
    assert(!sep_img4_root_key_canaries_are_valid(0));
    const sep_img4_runtime_callback_context_t runtime = {0};
    assert(sep_img4_runtime_verify_signature_rsa(
        empty_sequence, sizeof(empty_sequence), empty_sequence,
        sizeof(empty_sequence), empty_sequence, sizeof(empty_sequence),
        &runtime) == -1);
    assert(sep_img4_verify_rsa_signature_and_pin_root(
        &encoded, NULL, &encoded, &encoded) == -1);
}

int main(void) {
    test_properties();
    test_constraints();
    test_decode_and_digest();
    test_error_contracts_and_chain_anchor();
}
