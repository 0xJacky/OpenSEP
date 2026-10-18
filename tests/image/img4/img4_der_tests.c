#include "open_secure_rom/der.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

/*
 * These fixtures are built here, byte by byte, to the public IMG4 container
 * schema as documented by PongoOS lib/img4 (checkra1n/PongoOS, MIT):
 * https://github.com/checkra1n/PongoOS/blob/master/src/lib/img4/img4.c
 * No PongoOS code or data is copied into this file.
 */
typedef struct fixture_buffer {
    sep_u8 bytes[1024];
    sep_size_t length;
} fixture_buffer_t;

typedef struct public_img4_fixture {
    fixture_buffer_t payload_properties;
    fixture_buffer_t payload;
    fixture_buffer_t manifest;
    fixture_buffer_t restore_info;
    fixture_buffer_t img4;
    fixture_buffer_t certificate_properties;
} public_img4_fixture_t;

static void fixture_append(
    fixture_buffer_t *output,
    const void *data,
    sep_size_t length
) {
    if (length == 0) {
        return;
    }
    assert(output->length + length <= sizeof(output->bytes));
    memcpy(output->bytes + output->length, data, length);
    output->length += length;
}

static void fixture_append_length(
    fixture_buffer_t *output,
    sep_size_t length
) {
    if (length < 0x80) {
        const sep_u8 byte = (sep_u8)length;
        fixture_append(output, &byte, 1);
        return;
    }
    assert(length <= 0xff);
    const sep_u8 bytes[] = {0x81, (sep_u8)length};
    fixture_append(output, bytes, sizeof(bytes));
}

static fixture_buffer_t fixture_tlv(
    sep_u8 tag,
    const void *content,
    sep_size_t content_length
) {
    fixture_buffer_t output = {0};
    fixture_append(&output, &tag, 1);
    fixture_append_length(&output, content_length);
    fixture_append(&output, content, content_length);
    return output;
}

static fixture_buffer_t fixture_fourcc(sep_u32 value) {
    const sep_u8 bytes[] = {
        (sep_u8)(value >> 24),
        (sep_u8)(value >> 16),
        (sep_u8)(value >> 8),
        (sep_u8)value,
    };
    return fixture_tlv(SEP_DER_TAG_IA5_STRING, bytes, sizeof(bytes));
}

static fixture_buffer_t fixture_private(
    sep_u32 tag,
    const fixture_buffer_t *content
) {
    sep_u8 encoded_tag[5];
    sep_size_t tag_length = 0;
    do {
        encoded_tag[tag_length++] = tag & 0x7fU;
        tag >>= 7;
    } while (tag != 0);

    fixture_buffer_t output = {0};
    const sep_u8 first = 0xff;
    fixture_append(&output, &first, 1);
    while (tag_length != 0) {
        --tag_length;
        const sep_u8 byte = encoded_tag[tag_length] |
            (tag_length == 0 ? 0 : 0x80U);
        fixture_append(&output, &byte, 1);
    }
    fixture_append_length(&output, content->length);
    fixture_append(&output, content->bytes, content->length);
    return output;
}

static void fixture_append_buffer(
    fixture_buffer_t *output,
    const fixture_buffer_t *item
) {
    fixture_append(output, item->bytes, item->length);
}

static fixture_buffer_t fixture_property(
    sep_u32 tag,
    sep_u8 value_tag,
    const sep_u8 *value,
    sep_size_t value_length
) {
    const fixture_buffer_t key = fixture_fourcc(tag);
    const fixture_buffer_t encoded_value = fixture_tlv(
        value_tag,
        value,
        value_length
    );
    fixture_buffer_t sequence_content = {0};
    fixture_append_buffer(&sequence_content, &key);
    fixture_append_buffer(&sequence_content, &encoded_value);
    const fixture_buffer_t sequence = fixture_tlv(
        0x30,
        sequence_content.bytes,
        sequence_content.length
    );
    return fixture_private(tag, &sequence);
}

static public_img4_fixture_t make_public_img4_fixture(void) {
    enum {
        IMG4 = 0x494d4734U,
        IM4P = 0x494d3450U,
        IM4M = 0x494d344dU,
        IM4R = 0x494d3452U,
        MANB = 0x4d414e42U,
        MANP = 0x4d414e50U,
        PAYP = 0x50415950U,
        TEST = 0x54455354U,
    };
    public_img4_fixture_t fixture = {0};

    const sep_u8 property_value[] = {0xde, 0xad, 0xbe, 0xef};
    const fixture_buffer_t manifest_property = fixture_property(
        MANP,
        0x31,
        0,
        0
    );
    fixture_buffer_t object_dictionary_content = {0};
    fixture_append_buffer(&object_dictionary_content, &manifest_property);
    const fixture_buffer_t object_dictionary = fixture_tlv(
        0x30,
        object_dictionary_content.bytes,
        object_dictionary_content.length
    );

    fixture_buffer_t object_property_sequence_content = {0};
    const fixture_buffer_t object_property_key = fixture_fourcc(MANB);
    fixture_append_buffer(
        &object_property_sequence_content,
        &object_property_key
    );
    fixture_append_buffer(&object_property_sequence_content, &object_dictionary);
    const fixture_buffer_t object_property_sequence = fixture_tlv(
        0x30,
        object_property_sequence_content.bytes,
        object_property_sequence_content.length
    );
    const fixture_buffer_t object_property = fixture_private(
        MANB,
        &object_property_sequence
    );
    fixture_buffer_t manifest_set_content = {0};
    fixture_append_buffer(&manifest_set_content, &object_property);
    const fixture_buffer_t manifest_set = fixture_tlv(
        0x31,
        manifest_set_content.bytes,
        manifest_set_content.length
    );

    fixture_buffer_t payload_properties_content = {0};
    const fixture_buffer_t payp_magic = fixture_fourcc(PAYP);
    const fixture_buffer_t payp_set = fixture_tlv(0x31, 0, 0);
    fixture_append_buffer(&payload_properties_content, &payp_magic);
    fixture_append_buffer(&payload_properties_content, &payp_set);
    fixture.payload_properties = fixture_tlv(
        0x30,
        payload_properties_content.bytes,
        payload_properties_content.length
    );

    fixture_buffer_t compression_content = {0};
    const sep_u8 zero = 0;
    const sep_u8 size = 4;
    const fixture_buffer_t compression_type = fixture_tlv(0x02, &zero, 1);
    const fixture_buffer_t uncompressed_size = fixture_tlv(0x02, &size, 1);
    fixture_append_buffer(&compression_content, &compression_type);
    fixture_append_buffer(&compression_content, &uncompressed_size);
    const fixture_buffer_t compression = fixture_tlv(
        0x30,
        compression_content.bytes,
        compression_content.length
    );

    fixture_buffer_t payload_content = {0};
    const fixture_buffer_t payload_magic = fixture_fourcc(IM4P);
    const fixture_buffer_t payload_type = fixture_fourcc(0x73657069U);
    const sep_u8 version_bytes[] = {'1', '.', '0'};
    const fixture_buffer_t version = fixture_tlv(
        0x16,
        version_bytes,
        sizeof(version_bytes)
    );
    const fixture_buffer_t payload_data = fixture_tlv(
        0x04,
        property_value,
        sizeof(property_value)
    );
    const sep_u8 keybag_bytes[] = {0x11, 0x22};
    const fixture_buffer_t keybag = fixture_tlv(
        0x04,
        keybag_bytes,
        sizeof(keybag_bytes)
    );
    fixture_append_buffer(&payload_content, &payload_magic);
    fixture_append_buffer(&payload_content, &payload_type);
    fixture_append_buffer(&payload_content, &version);
    fixture_append_buffer(&payload_content, &payload_data);
    fixture_append_buffer(&payload_content, &keybag);
    fixture_append_buffer(&payload_content, &compression);
    const fixture_buffer_t encoded_properties = fixture_tlv(
        0xa0,
        fixture.payload_properties.bytes,
        fixture.payload_properties.length
    );
    fixture_append_buffer(&payload_content, &encoded_properties);
    fixture.payload = fixture_tlv(
        0x30,
        payload_content.bytes,
        payload_content.length
    );

    fixture_buffer_t manifest_content = {0};
    const fixture_buffer_t manifest_magic = fixture_fourcc(IM4M);
    const sep_u8 two = 2;
    const fixture_buffer_t manifest_version = fixture_tlv(0x02, &two, 1);
    const sep_u8 signature_byte = 0x5a;
    const fixture_buffer_t signature = fixture_tlv(
        0x04,
        &signature_byte,
        1
    );
    const fixture_buffer_t certificates = fixture_tlv(0x30, 0, 0);
    fixture_append_buffer(&manifest_content, &manifest_magic);
    fixture_append_buffer(&manifest_content, &manifest_version);
    fixture_append_buffer(&manifest_content, &manifest_set);
    fixture_append_buffer(&manifest_content, &signature);
    fixture_append_buffer(&manifest_content, &certificates);
    fixture.manifest = fixture_tlv(
        0x30,
        manifest_content.bytes,
        manifest_content.length
    );

    fixture_buffer_t restore_content = {0};
    const fixture_buffer_t restore_magic = fixture_fourcc(IM4R);
    const fixture_buffer_t nonce_set = fixture_tlv(0x31, 0, 0);
    fixture_append_buffer(&restore_content, &restore_magic);
    fixture_append_buffer(&restore_content, &nonce_set);
    fixture.restore_info = fixture_tlv(
        0x30,
        restore_content.bytes,
        restore_content.length
    );

    fixture_buffer_t img4_content = {0};
    const fixture_buffer_t img4_magic = fixture_fourcc(IMG4);
    const fixture_buffer_t encoded_manifest = fixture_tlv(
        0xa0,
        fixture.manifest.bytes,
        fixture.manifest.length
    );
    const fixture_buffer_t encoded_restore = fixture_tlv(
        0xa1,
        fixture.restore_info.bytes,
        fixture.restore_info.length
    );
    fixture_append_buffer(&img4_content, &img4_magic);
    fixture_append_buffer(&img4_content, &fixture.payload);
    fixture_append_buffer(&img4_content, &encoded_manifest);
    fixture_append_buffer(&img4_content, &encoded_restore);
    fixture.img4 = fixture_tlv(
        0x30,
        img4_content.bytes,
        img4_content.length
    );

    const fixture_buffer_t certificate_property = fixture_property(
        TEST,
        0x04,
        property_value,
        sizeof(property_value)
    );
    fixture_buffer_t certificate_set_content = {0};
    fixture_append_buffer(&certificate_set_content, &certificate_property);
    const fixture_buffer_t certificate_set = fixture_tlv(
        0x31,
        certificate_set_content.bytes,
        certificate_set_content.length
    );
    fixture_buffer_t certificate_sequence_content = {0};
    fixture_append_buffer(&certificate_sequence_content, &payp_magic);
    fixture_append_buffer(&certificate_sequence_content, &certificate_set);
    const fixture_buffer_t certificate_sequence = fixture_tlv(
        0x30,
        certificate_sequence_content.bytes,
        certificate_sequence_content.length
    );
    fixture_append_buffer(
        &fixture.certificate_properties,
        &certificate_sequence
    );
    return fixture;
}

static sep_der_item_t fixture_item(const fixture_buffer_t *fixture) {
    const sep_der_item_t item = {fixture->bytes, fixture->length};
    return item;
}

static void test_img4_payload_decoders(
    const public_img4_fixture_t *fixture
) {
    const sep_der_item_t payload_item = fixture_item(&fixture->payload);
    sep_der_img4_payload_t payload = {0};
    assert(sep_der_img4_decode_payload_with_properties(
        &payload_item,
        &payload
    ) == SEP_DER_SUCCESS);
    assert(payload.payload.length == 4);
    assert(payload.keybag.length == 2);
    assert(payload.compression.length == 6);
    const sep_der_item_t *properties = (const sep_der_item_t *)(
        (const sep_u8 *)&payload + 96
    );
    assert(properties->length == fixture->payload_properties.length);

    const sep_der_item_t compression = payload.compression;
    sep_der_img4_payload_compression_t decoded_compression = {0};
    assert(sep_der_img4_decode_payload_compression(
        &compression,
        &decoded_compression
    ) == SEP_DER_SUCCESS);
    assert(decoded_compression.uncompressed_size.length == 1);
    assert(decoded_compression.uncompressed_size.data[0] == 4);

    sep_der_img4_payload_properties_t decoded_properties;
    const sep_der_item_t properties_item = fixture_item(
        &fixture->payload_properties
    );
    assert(sep_der_img4_decode_payload_properties(
        &properties_item,
        &decoded_properties
    ) == SEP_DER_SUCCESS);
    assert(decoded_properties.properties.length == 0);

    memset(&payload, 0, sizeof(payload));
    assert(sep_der_img4_decode_payload(&payload_item, &payload) ==
        SEP_DER_SUCCESS);
    assert(payload.payload.length == 4);
    assert(payload.payload_hash[0] == 0);

    const sep_u8 invalid_compression_bytes[] = {
        0x02, 0x01, 0x02,
        0x02, 0x01, 0x04,
    };
    const sep_der_item_t invalid_compression = {
        invalid_compression_bytes,
        sizeof(invalid_compression_bytes),
    };
    assert(sep_der_img4_decode_payload_compression(
        &invalid_compression,
        &decoded_compression
    ) == SEP_DER_INVALID_ARGUMENT);

    fixture_buffer_t bad_properties = fixture->payload_properties;
    bad_properties.bytes[4] = 'X';
    const sep_der_item_t bad_properties_item = fixture_item(&bad_properties);
    assert(sep_der_img4_decode_payload_properties(
        &bad_properties_item,
        &decoded_properties
    ) == SEP_DER_UNEXPECTED_TAG);
}

static void test_img4_envelope_and_manifest(
    const public_img4_fixture_t *fixture
) {
    const sep_der_item_t img4_item = fixture_item(&fixture->img4);
    sep_der_img4_decoded_t envelope = {0};
    assert(sep_der_img4_decode(&img4_item, &envelope) == SEP_DER_SUCCESS);
    assert(envelope.payload.length == fixture->payload.length);
    assert(envelope.payload.data[0] == 0x30);
    assert(envelope.manifest.length == fixture->manifest.length);
    assert(envelope.restore_info.length == fixture->restore_info.length);

    sep_der_img4_manifest_t manifest = {0};
    const sep_der_item_t manifest_item = fixture_item(&fixture->manifest);
    assert(sep_der_img4_decode_manifest(&manifest_item, &manifest) ==
        SEP_DER_SUCCESS);
    assert(manifest.properties.data[0] == 0x31);
    assert(manifest.signature.length == 1);

    const sep_der_item_spec_t manifest_specs[] = {
        {0, SEP_DER_TAG_IA5_STRING, 0},
        {16, SEP_DER_TAG_INTEGER, 0},
        {32, SEP_DER_TAG_SET, SEP_DER_SAVE_ENCODING},
        {48, SEP_DER_TAG_OCTET_STRING, 0},
        {64, SEP_DER_TAG_SEQUENCE, 0},
    };
    sep_der_img4_manifest_t common = {0};
    assert(sep_der_img4_decode_manifest_common(
        &manifest_item,
        5,
        manifest_specs,
        &common,
        0x494d344dU
    ) == SEP_DER_SUCCESS);

    fixture_buffer_t unsigned_manifest_content = {0};
    fixture_append(&unsigned_manifest_content, manifest.magic.data - 2, 6);
    fixture_append(&unsigned_manifest_content, manifest.version.data - 2, 3);
    fixture_append(
        &unsigned_manifest_content,
        manifest.properties.data,
        manifest.properties.length
    );
    const fixture_buffer_t unsigned_manifest = fixture_tlv(
        0x30,
        unsigned_manifest_content.bytes,
        unsigned_manifest_content.length
    );
    const sep_der_item_t unsigned_manifest_item = fixture_item(
        &unsigned_manifest
    );
    memset(&manifest, 0, sizeof(manifest));
    assert(sep_der_img4_decode_unsigned_manifest(
        &unsigned_manifest_item,
        &manifest
    ) == SEP_DER_SUCCESS);

    fixture_buffer_t certificate_content = unsigned_manifest_content;
    certificate_content.bytes[5] = 'C';
    const sep_u8 signature_byte = 0x33;
    const fixture_buffer_t signature = fixture_tlv(
        0x04,
        &signature_byte,
        1
    );
    fixture_append_buffer(&certificate_content, &signature);
    const fixture_buffer_t certificate = fixture_tlv(
        0x30,
        certificate_content.bytes,
        certificate_content.length
    );
    const sep_der_item_t certificate_item = fixture_item(&certificate);
    memset(&manifest, 0, sizeof(manifest));
    assert(sep_der_img4_decode_certificate(&certificate_item, &manifest) ==
        SEP_DER_SUCCESS);

    fixture_buffer_t unsigned_certificate_content = unsigned_manifest_content;
    unsigned_certificate_content.bytes[5] = 'C';
    const fixture_buffer_t unsigned_certificate = fixture_tlv(
        0x30,
        unsigned_certificate_content.bytes,
        unsigned_certificate_content.length
    );
    const sep_der_item_t unsigned_certificate_item = fixture_item(
        &unsigned_certificate
    );
    memset(&manifest, 0, sizeof(manifest));
    assert(sep_der_img4_decode_unsigned_certificate(
        &unsigned_certificate_item,
        &manifest
    ) == SEP_DER_SUCCESS);

    fixture_buffer_t bad_version = fixture->manifest;
    const sep_u8 version_pattern[] = {0x02, 0x01, 0x02};
    sep_u8 *version = 0;
    for (sep_size_t index = 0;
         index + sizeof(version_pattern) <= bad_version.length;
         ++index) {
        if (memcmp(
                bad_version.bytes + index,
                version_pattern,
                sizeof(version_pattern)
            ) == 0) {
            version = bad_version.bytes + index;
            break;
        }
    }
    assert(version != 0);
    version[2] = 3;
    const sep_der_item_t bad_version_item = fixture_item(&bad_version);
    assert(sep_der_img4_decode_manifest(&bad_version_item, &manifest) ==
        SEP_DER_UNEXPECTED_TAG);
}

static void test_restore_and_properties(
    const public_img4_fixture_t *fixture
) {
    const sep_der_item_t restore_item = fixture_item(&fixture->restore_info);
    sep_der_img4_restore_info_t restore = {0};
    assert(sep_der_img4_decode_restore_info(&restore_item, &restore) ==
        SEP_DER_SUCCESS);
    assert(restore.nonce.length == 0);
    assert(sep_der_img4_decode_restore_info(0, &restore) == SEP_DER_SUCCESS);

    const sep_der_item_t manifest_item = fixture_item(&fixture->manifest);
    sep_img4_decode_context_t image = {0};
    assert(sep_der_img4_decode_manifest(&manifest_item, &image.manifest) ==
        SEP_DER_SUCCESS);
    sep_der_item_t object_dictionary = {0};
    sep_der_item_t manifest_properties = {0};
    assert(sep_der_img4_decode_parse_manifest_properties(
        &image,
        &object_dictionary,
        &manifest_properties
    ) == SEP_DER_SUCCESS);
    assert(object_dictionary.length != 0);
    assert(manifest_properties.length == 0);
    assert(sep_der_img4_decode_parse_manifest_properties_internal(
        &image,
        &object_dictionary,
        0,
        0x4d414e42U
    ) == SEP_DER_SUCCESS);

    const sep_der_item_t certificate_properties = fixture_item(
        &fixture->certificate_properties
    );
    sep_der_item_t value = {0};
    assert(sep_der_img4_decode_parse_certificate_properties(
        &certificate_properties,
        0x54455354U,
        &value
    ) == SEP_DER_SUCCESS);
    assert(value.length == 4 && value.data[0] == 0xde);
    assert(sep_der_img4_decode_parse_certificate_properties(
        &certificate_properties,
        0x4d495353U,
        &value
    ) == SEP_DER_END_OF_SEQUENCE);
}

static void test_malformed_and_partial_cases(
    const public_img4_fixture_t *fixture
) {
    sep_der_img4_decoded_t envelope = {0};
    sep_der_item_t partial = fixture_item(&fixture->img4);
    --partial.length;
    assert(sep_der_img4_decode(&partial, &envelope) == SEP_DER_DECODE_ERROR);

    fixture_buffer_t trailing = fixture->img4;
    trailing.bytes[trailing.length++] = 0;
    const sep_der_item_t trailing_item = fixture_item(&trailing);
    assert(sep_der_img4_decode(&trailing_item, &envelope) ==
        SEP_DER_BUFFER_OVERFLOW);

    fixture_buffer_t wrong_magic = fixture->img4;
    wrong_magic.bytes[4] = 'X';
    const sep_der_item_t wrong_magic_item = fixture_item(&wrong_magic);
    assert(sep_der_img4_decode(&wrong_magic_item, &envelope) ==
        SEP_DER_UNEXPECTED_TAG);

    sep_der_img4_manifest_t manifest = {0};
    sep_der_item_t partial_manifest = fixture_item(&fixture->manifest);
    --partial_manifest.length;
    assert(sep_der_img4_decode_manifest(&partial_manifest, &manifest) ==
        SEP_DER_DECODE_ERROR);

    assert(sep_der_img4_decode(0, &envelope) == SEP_DER_INVALID_ARGUMENT);
    assert(sep_der_img4_decode_payload(0, 0) == SEP_DER_INVALID_ARGUMENT);
    assert(sep_der_img4_decode_manifest(0, &manifest) ==
        SEP_DER_INVALID_ARGUMENT);
}

int main(void) {
    const public_img4_fixture_t fixture = make_public_img4_fixture();
    test_img4_payload_decoders(&fixture);
    test_img4_envelope_and_manifest(&fixture);
    test_restore_and_properties(&fixture);
    test_malformed_and_partial_cases(&fixture);
}
