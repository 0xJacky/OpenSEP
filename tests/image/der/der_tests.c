#include "open_secure_rom/der.h"

#include <assert.h>
#include <string.h>

static sep_size_t encode_private_tag(
    sep_u8 *output,
    sep_u32 tag,
    const sep_u8 *content,
    sep_size_t content_length
) {
    sep_u8 encoded_tag[5];
    sep_size_t count = 0;
    do {
        encoded_tag[count++] = tag & 0x7fU;
        tag >>= 7;
    } while (tag != 0);

    sep_size_t cursor = 0;
    output[cursor++] = 0xff;
    while (count != 0) {
        --count;
        output[cursor++] = encoded_tag[count] | (count == 0 ? 0 : 0x80U);
    }
    output[cursor++] = (sep_u8)content_length;
    memcpy(output + cursor, content, content_length);
    return cursor + content_length;
}

static void test_item_decoding(void) {
    const sep_u8 sequence_bytes[] = {0x30, 0x03, 0x02, 0x01, 0x7f};
    const sep_der_item_t sequence_item = {
        sequence_bytes,
        sizeof(sequence_bytes),
    };
    sep_der_decoded_info_t decoded;
    assert(sep_der_decode_item(&sequence_item, &decoded) == SEP_DER_SUCCESS);
    assert(decoded.tag == SEP_DER_TAG_SEQUENCE);
    assert(decoded.content.data == sequence_bytes + 2);
    assert(decoded.content.length == 3);

    const sep_u8 incomplete_bytes[] = {0x04, 0x05, 0xaa};
    const sep_der_item_t incomplete = {
        incomplete_bytes,
        sizeof(incomplete_bytes),
    };
    assert(sep_der_decode_item(&incomplete, &decoded) ==
        SEP_DER_DECODE_ERROR);
    assert(sep_der_decode_item_partial_buffer(&incomplete, &decoded, 1) ==
        SEP_DER_SUCCESS);
    assert(decoded.content.length == 5);

    sep_size_t declared_length = 0;
    assert(sep_der_decode_item_partial_buffer_get_length(
        &incomplete,
        &decoded,
        &declared_length
    ) == SEP_DER_SUCCESS);
    assert(declared_length == 5);
    assert(decoded.content.length == 1);

    sep_u8 long_form[131] = {0x04, 0x81, 0x80};
    const sep_der_item_t long_item = {long_form, sizeof(long_form)};
    assert(sep_der_decode_item(&long_item, &decoded) == SEP_DER_SUCCESS);
    assert(decoded.content.length == 0x80);

    const sep_u8 noncanonical_short[] = {0x04, 0x81, 0x7f};
    const sep_der_item_t noncanonical_item = {
        noncanonical_short,
        sizeof(noncanonical_short),
    };
    assert(sep_der_decode_item_partial_buffer(
        &noncanonical_item,
        &decoded,
        1
    ) == SEP_DER_DECODE_ERROR);

    const sep_u8 leading_zero_length[] = {0x04, 0x82, 0x00, 0x80};
    const sep_der_item_t leading_zero_item = {
        leading_zero_length,
        sizeof(leading_zero_length),
    };
    assert(sep_der_decode_item_partial_buffer(
        &leading_zero_item,
        &decoded,
        1
    ) == SEP_DER_DECODE_ERROR);

    const sep_u8 indefinite[] = {0x04, 0x80};
    const sep_der_item_t indefinite_item = {indefinite, sizeof(indefinite)};
    assert(sep_der_decode_item(&indefinite_item, &decoded) ==
        SEP_DER_DECODE_ERROR);

    const sep_u8 long_tag[] = {0x9f, 0x81, 0x00, 0x00};
    const sep_der_item_t long_tag_item = {long_tag, sizeof(long_tag)};
    assert(sep_der_decode_item(&long_tag_item, &decoded) == SEP_DER_SUCCESS);
    assert(decoded.tag == 0x8000000000000080ULL);

    sep_size_t encoded_length = 0;
    const sep_u8 partial_sequence[] = {0x30, 0x05, 0x02};
    assert(sep_der_sequence_encoded_length(
        partial_sequence,
        sizeof(partial_sequence),
        &encoded_length
    ) == 1);
    assert(encoded_length == 7);
}

static void test_primitive_parsers(void) {
    const sep_u8 bits[] = {3, 0xa8};
    const sep_der_item_t bit_contents = {bits, sizeof(bits)};
    sep_der_item_t bit_bytes;
    sep_u8 unused;
    assert(sep_der_parse_bit_string(&bit_contents, &bit_bytes, &unused) ==
        SEP_DER_SUCCESS);
    assert(unused == 3 && bit_bytes.data == bits + 1 && bit_bytes.length == 1);

    const sep_u8 bad_bits[] = {3, 0xab};
    const sep_der_item_t bad_bit_contents = {bad_bits, sizeof(bad_bits)};
    assert(sep_der_parse_bit_string(
        &bad_bit_contents,
        &bit_bytes,
        &unused
    ) == SEP_DER_DECODE_ERROR);

    const sep_u8 empty_bits[] = {0};
    const sep_der_item_t empty_bit_contents = {empty_bits, 1};
    assert(sep_der_parse_bit_string(
        &empty_bit_contents,
        &bit_bytes,
        &unused
    ) == SEP_DER_SUCCESS);
    assert(bit_bytes.data == 0 && bit_bytes.length == 0);

    const sep_u8 true_byte = 0xff;
    const sep_der_item_t true_item = {&true_byte, 1};
    sep_bool boolean = 0;
    assert(sep_der_parse_boolean(&true_item, &boolean) == SEP_DER_SUCCESS);
    assert(boolean == 1);
    const sep_u8 bad_boolean_byte = 1;
    const sep_der_item_t bad_boolean = {&bad_boolean_byte, 1};
    assert(sep_der_parse_boolean(&bad_boolean, &boolean) ==
        SEP_DER_DECODE_ERROR);

    const sep_u8 maximum[] = {
        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const sep_der_item_t maximum_item = {maximum, sizeof(maximum)};
    sep_u64 value64 = 0;
    assert(sep_der_parse_integer64(&maximum_item, &value64) ==
        SEP_DER_SUCCESS);
    assert(value64 == UINT64_MAX);

    const sep_u8 noncanonical_integer[] = {0x00, 0x7f};
    const sep_der_item_t noncanonical = {
        noncanonical_integer,
        sizeof(noncanonical_integer),
    };
    assert(sep_der_parse_integer64(&noncanonical, &value64) ==
        SEP_DER_DECODE_ERROR);

    const sep_u8 overflow32[] = {0x01, 0x00, 0x00, 0x00, 0x00};
    const sep_der_item_t overflow32_item = {overflow32, sizeof(overflow32)};
    sep_u32 value32 = 0;
    assert(sep_der_parse_integer(&overflow32_item, &value32) ==
        SEP_DER_BUFFER_OVERFLOW);
}

static void test_sequence_parsing(void) {
    const sep_u8 encoded[] = {
        0x30, 0x08,
        0x02, 0x01, 0x05,
        0x04, 0x03, 0xaa, 0xbb, 0xcc,
    };
    const sep_der_item_t item = {encoded, sizeof(encoded)};
    sep_u64 tag = 0;
    sep_der_sequence_t sequence;
    assert(sep_der_decode_sequence_init(&item, &tag, &sequence) ==
        SEP_DER_SUCCESS);
    assert(tag == SEP_DER_TAG_SEQUENCE);

    sep_der_decoded_info_t decoded;
    assert(sep_der_decode_sequence_next(&sequence, &decoded) ==
        SEP_DER_SUCCESS);
    assert(decoded.tag == SEP_DER_TAG_INTEGER && decoded.content.data[0] == 5);
    assert(sep_der_decode_sequence_next(&sequence, &decoded) ==
        SEP_DER_SUCCESS);
    assert(decoded.tag == 0x04 && decoded.content.length == 3);
    assert(sep_der_decode_sequence_next(&sequence, &decoded) ==
        SEP_DER_END_OF_SEQUENCE);

    const sep_u8 set_bytes[] = {0x31, 0x00};
    const sep_der_item_t set_item = {set_bytes, sizeof(set_bytes)};
    assert(sep_der_decode_sequence_init(&set_item, &tag, &sequence) ==
        SEP_DER_SUCCESS);
    assert(tag == SEP_DER_TAG_SET);

    const sep_u8 octet_only[] = {0x04, 0x00};
    const sep_der_item_t octet_item = {octet_only, sizeof(octet_only)};
    assert(sep_der_decode_sequence_init(&octet_item, &tag, &sequence) ==
        SEP_DER_UNEXPECTED_TAG);

    struct output {
        sep_der_item_t integer;
        sep_der_item_t optional;
        sep_der_item_t octets;
    } output;
    const sep_der_item_spec_t specs[] = {
        {offsetof(struct output, integer), SEP_DER_TAG_INTEGER, 0},
        {offsetof(struct output, optional), 0x05, SEP_DER_OPTIONAL},
        {offsetof(struct output, octets), 0x04, SEP_DER_SAVE_ENCODING},
    };
    memset(&output, 0xaa, sizeof(output));
    assert(sep_der_parse_sequence_to_object(
        &item,
        3,
        specs,
        &output,
        sizeof(output),
        sizeof(output)
    ) == SEP_DER_SUCCESS);
    assert(output.integer.length == 1 && output.integer.data[0] == 5);
    assert(output.optional.data == 0 && output.optional.length == 0);
    assert(output.octets.data == encoded + 5 && output.octets.length == 5);

    const sep_der_item_spec_t required_missing[] = {
        {0, SEP_DER_TAG_INTEGER, 0},
        {16, 0x05, 0},
    };
    sep_der_item_t missing_output[2];
    const sep_u8 integer_only[] = {0x30, 0x03, 0x02, 0x01, 1};
    const sep_der_item_t integer_only_item = {
        integer_only,
        sizeof(integer_only),
    };
    assert(sep_der_parse_sequence_to_object(
        &integer_only_item,
        2,
        required_missing,
        missing_output,
        sizeof(missing_output),
        sizeof(missing_output)
    ) == SEP_DER_INCOMPLETE_SEQUENCE);

    assert(sep_der_parse_sequence_to_object(
        &item,
        1,
        specs,
        &output,
        sizeof(output),
        0
    ) == SEP_DER_DECODE_ERROR);
    assert(sep_der_parse_sequence_to_object(
        &integer_only_item,
        1,
        specs,
        &output,
        8,
        0
    ) == SEP_DER_BUFFER_OVERFLOW);

    const sep_der_item_spec_t any_skip = {0, 0, SEP_DER_ANY_TAG | SEP_DER_SKIP};
    assert(sep_der_parse_sequence_to_object(
        &integer_only_item,
        1,
        &any_skip,
        &output,
        sizeof(output),
        0
    ) == SEP_DER_SUCCESS);

    memset(&output, 0, sizeof(output));
    assert(sep_der_parse_sequence(
        &item,
        3,
        specs,
        &output,
        sizeof(output)
    ) == SEP_DER_SUCCESS);
}

static void test_oid_and_img4_helpers(void) {
    const sep_u8 oid_bytes[] = {0x2a, 0x86, 0x48};
    const sep_der_item_t oid = {oid_bytes, sizeof(oid_bytes)};
    assert(sep_der_oid_compare(&oid, &oid) == 1);
    assert(sep_der_oid_compare(&oid, 0) == 0);
    const sep_u8 different_oid_bytes[] = {0x2a, 0x86, 0x49};
    const sep_der_item_t different_oid = {
        different_oid_bytes,
        sizeof(different_oid_bytes),
    };
    assert(sep_der_oid_compare(&oid, &different_oid) == 0);

    const sep_u8 magic_bytes[] = {'I', 'M', 'G', '4'};
    const sep_der_item_t magic_item = {magic_bytes, sizeof(magic_bytes)};
    assert(sep_der_img4_decode_tag_compare(&magic_item, 0x494d4734) == 0);
    assert(sep_der_img4_decode_tag_compare(&magic_item, 0x494d4735) == -1);
    const sep_der_item_t short_magic = {magic_bytes, 3};
    const sep_der_item_t long_magic = {magic_bytes, 5};
    assert(sep_der_img4_decode_tag_compare(&short_magic, 0) == -1);
    assert(sep_der_img4_decode_tag_compare(&long_magic, 0) == 1);

    const sep_u8 property_sequence[] = {
        0x30, 0x0a,
        0x16, 0x04, 'I', 'M', 'G', '4',
        0x04, 0x02, 0xaa, 0xbb,
    };
    const sep_der_item_t property = {
        property_sequence,
        sizeof(property_sequence),
    };
    const sep_u64 expected_tag = 0xe0000000494d4734ULL;
    sep_img4_der_element_t output[2] = {0};
    assert(sep_der_img4_decode_property_with_item(
        &property,
        expected_tag,
        0x04,
        output
    ) == SEP_DER_SUCCESS);
    assert(output[0].tag == expected_tag);
    assert(output[1].tag == 0x04);
    assert(output[1].item.length == 2 && output[1].item.data[0] == 0xaa);
    assert(sep_der_img4_decode_property_with_item(
        &property,
        expected_tag + 1,
        0x04,
        output
    ) == SEP_DER_UNEXPECTED_TAG);

    sep_u8 tagged_property[32];
    const sep_size_t tagged_length = encode_private_tag(
        tagged_property,
        0x494d4734,
        property_sequence,
        sizeof(property_sequence)
    );
    const sep_der_item_t content = {tagged_property, tagged_length};
    memset(output, 0, sizeof(output));
    assert(sep_der_img4_decode_find_property(
        &content,
        expected_tag,
        0x04,
        output
    ) == SEP_DER_SUCCESS);
    assert(output[1].item.length == 2);

    sep_der_sequence_t property_sequence_cursor;
    assert(sep_der_decode_sequence_content_init(
        &content,
        &property_sequence_cursor
    ) == SEP_DER_SUCCESS);
    memset(output, 0, sizeof(output));
    assert(sep_der_img4_decode_find_property_in_sequence(
        &property_sequence_cursor,
        expected_tag,
        0x04,
        output
    ) == SEP_DER_SUCCESS);

    sep_der_item_t found;
    assert(sep_der_img4_decode_content_find_item_with_tag(
        &content,
        expected_tag,
        &found
    ) == SEP_DER_SUCCESS);
    assert(found.length == sizeof(property_sequence));
    assert(sep_der_img4_decode_content_find_item_with_tag(
        &content,
        0x05,
        &found
    ) == SEP_DER_END_OF_SEQUENCE);
}

int main(void) {
    test_item_decoding();
    test_primitive_parsers();
    test_sequence_parsing();
    test_oid_and_img4_helpers();
}
