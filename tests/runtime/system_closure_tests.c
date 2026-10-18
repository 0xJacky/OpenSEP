#include "open_secure_rom/crypto_hmac.h"
#include "open_secure_rom/system_closure.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct memory_reader {
    sep_u64 base;
    const sep_u8 *bytes;
    sep_size_t length;
    sep_size_t calls;
} memory_reader_t;

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    abort();
}

void sep_platform_key_material_transform_noop(
    const char *label,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
) {
    (void)label;
    (void)source;
    (void)source_length;
    (void)output;
    (void)output_length;
}

void sep_optional_configuration_key48_initialize_from_data(
    sep_optional_configuration_key48_t *output,
    const void *data,
    sep_size_t length
) {
    assert(length == sizeof(output->bytes));
    memcpy(output->bytes, data, length);
    output->present = 1;
}

void sep_optional_research_seed_initialize_from_data(
    sep_optional_research_seed_t *output,
    const void *data,
    sep_size_t length
) {
    assert(length == sizeof(output->bytes));
    memcpy(output->bytes, data, length);
    output->present = 1;
}

static sep_bool read_memory(
    void *context,
    sep_u64 source_address,
    void *destination,
    sep_size_t length
) {
    memory_reader_t *reader = context;
    if (source_address < reader->base ||
        source_address - reader->base > reader->length ||
        length > reader->length - (source_address - reader->base)) {
        return 0;
    }
    memcpy(
        destination,
        reader->bytes + (source_address - reader->base),
        length
    );
    ++reader->calls;
    return 1;
}

static void make_hmac_tag(
    const sep_u8 key[32],
    const void *message,
    sep_size_t message_length,
    sep_u8 tag[16]
) {
    sep_u8 mac[32];
    sep_hmac_by_bit_length(
        256,
        message,
        message_length,
        key,
        32,
        mac,
        sizeof(mac)
    );
    memcpy(tag, mac, 16);
}

static void test_exception_layout_and_record(void) {
    assert(open_secure_rom_exception_stack_pointer_is_valid(0x04024001));
    assert(open_secure_rom_exception_stack_pointer_is_valid(0x0402c000));
    assert(open_secure_rom_exception_stack_pointer_is_valid(0x0402c001));
    assert(open_secure_rom_exception_stack_pointer_is_valid(0x04030000));
    assert(!open_secure_rom_exception_stack_pointer_is_valid(0x04024000));
    assert(!open_secure_rom_exception_stack_pointer_is_valid(0x04030001));

    const sep_exception_frame_t frame = {
        .frame_pointer = 0x1111111111111111ULL,
        .link_register = 0x2222222222222222ULL,
        .stack_pointer = 0x0402ff00,
        .saved_program_status = 0x33445566,
        .exception_link_register = 0x4444444444444444ULL,
        .fault_address = 0x5555555555555555ULL,
        .exception_syndrome = 0x0000000096abcdefULL,
    };
    sep_u8 event_log[64];
    for (sep_size_t index = 0; index < sizeof(event_log); ++index) {
        event_log[index] = (sep_u8)(index ^ 0x5a);
    }
    open_secure_rom_exception_panic_record_t record;
    open_secure_rom_exception_panic_record_initialize(
        &record,
        4,
        &frame,
        0x66778899,
        event_log
    );
    assert(record.vector_kind == 4);
    assert(record.exception_link_register == frame.exception_link_register);
    assert(record.exception_syndrome == (sep_u32)frame.exception_syndrome);
    assert(record.exception_class == ((sep_u32)frame.exception_syndrome >> 26));
    assert(record.instruction_specific_syndrome ==
           ((sep_u32)frame.exception_syndrome & 0x01ffffff));
    assert(record.fault_address == frame.fault_address);
    assert(record.stack_pointer == frame.stack_pointer);
    assert(record.link_register == frame.link_register);
    assert(record.saved_program_status == frame.saved_program_status);
    assert(record.platform_context == 0x66778899);
    assert(memcmp(record.event_log, event_log, sizeof(event_log)) == 0);
    for (sep_size_t index = 0; index < 31; ++index) {
        assert(record.return_addresses[index] == 0);
    }
}

static void test_shared_region_copy_and_load(void) {
    sep_u8 source[0x8000];
    sep_u8 destination[0x8000];
    for (sep_size_t index = 0; index < sizeof(source); ++index) {
        source[index] = (sep_u8)(index * 13 + 7);
    }
    memory_reader_t reader = {
        .base = 0x00100000,
        .bytes = source,
        .length = sizeof(source),
    };
    memset(destination, 0, sizeof(destination));
    assert(open_secure_rom_shared_region_copy_page_checked(
        reader.base,
        destination,
        123,
        read_memory,
        &reader
    ) == OPEN_SECURE_ROM_SHARED_REGION_OK);
    assert(memcmp(destination, source, 123) == 0);
    assert(open_secure_rom_shared_region_copy_page_checked(
        reader.base + 1,
        destination,
        1,
        read_memory,
        &reader
    ) == OPEN_SECURE_ROM_SHARED_REGION_SOURCE_ALIGNMENT);
    assert(open_secure_rom_shared_region_copy_page_checked(
        reader.base,
        destination,
        0x4001,
        read_memory,
        &reader
    ) == OPEN_SECURE_ROM_SHARED_REGION_PAGE_LENGTH);

    source[0] = 0x30;
    source[1] = 0x82;
    source[2] = 0x50;
    source[3] = 0x00;
    reader.calls = 0;
    sep_size_t encoded_length = 0;
    memset(destination, 0xa5, sizeof(destination));
    assert(open_secure_rom_shared_region_load_image_checked(
        reader.base,
        destination,
        sizeof(destination),
        read_memory,
        &reader,
        &encoded_length
    ) == OPEN_SECURE_ROM_SHARED_REGION_OK);
    assert(encoded_length == 0x5004);
    assert(reader.calls == 2);
    assert(memcmp(destination, source, encoded_length) == 0);
    for (sep_size_t index = encoded_length;
         index < sizeof(destination);
         ++index) {
        assert(destination[index] == 0);
    }
    assert(open_secure_rom_shared_region_load_image_checked(
        reader.base,
        destination,
        sizeof(destination) - 1,
        read_memory,
        &reader,
        &encoded_length
    ) == OPEN_SECURE_ROM_SHARED_REGION_CAPACITY_ALIGNMENT);
}

static void test_shared_region_payload_plan(void) {
    sep_u8 region[0xc000];
    sep_shared_image_context_t image;
    memset(&image, 0, sizeof(image));
    image.payload_data = region + 0x100;
    image.payload_size = 0x4001;
    image.manifest_data = region + 0xa000;
    image.manifest_size = 0x123;
    open_secure_rom_shared_region_payload_plan_t plan;
    assert(open_secure_rom_shared_region_plan_payload(
        (sep_u64)(uintptr_t)region,
        sizeof(region),
        &image,
        &plan
    ) == OPEN_SECURE_ROM_SHARED_REGION_OK);
    assert(plan.payload_destination == (sep_u64)(uintptr_t)region);
    assert(plan.payload_length == 0x4001);
    assert(plan.payload_capacity == 0x8000);
    assert(plan.manifest_destination ==
           (sep_u64)(uintptr_t)region + 0x8000);
    assert(plan.manifest_length == 0x123);
    image.manifest_size = 0x5000;
    assert(open_secure_rom_shared_region_plan_payload(
        (sep_u64)(uintptr_t)region,
        sizeof(region),
        &image,
        &plan
    ) == OPEN_SECURE_ROM_SHARED_REGION_ENCODED_TOO_LARGE);
}

static void test_provisioning_payloads(void) {
    sep_platform_provisioning_state_t state __attribute__((aligned(8)));
    memset(&state, 0, sizeof(state));
    sep_u8 artm[32];
    for (sep_size_t index = 0; index < 16; ++index) {
        artm[index] = (sep_u8)(0x80 + index);
    }
    sep_u8 zero_key[32] = { 0 };
    sep_u8 artm_message[17] = { 1 };
    memcpy(artm_message + 1, artm, 16);
    make_hmac_tag(zero_key, artm_message, sizeof(artm_message), artm + 16);
    assert(open_secure_rom_provisioning_install_artm_from_payload(
        &state,
        artm
    ));
    assert(state.bytes[88] == 1);
    assert(memcmp(&state.bytes[89], zero_key, sizeof(zero_key)) == 0);
    artm[31] ^= 1;
    assert(!open_secure_rom_provisioning_install_artm_from_payload(
        &state,
        artm
    ));

    sep_u8 research[86] = { 0 };
    research[0] = 1;
    for (sep_size_t index = 0; index < 48; ++index) {
        research[1 + index] = (sep_u8)(index + 1);
    }
    research[49] = 1;
    for (sep_size_t index = 0; index < 20; ++index) {
        research[50 + index] = (sep_u8)(0xf0 - index);
    }
    sep_u8 research_message[71] = { 2 };
    memcpy(research_message + 1, research, 70);
    make_hmac_tag(
        &state.bytes[89],
        research_message,
        sizeof(research_message),
        research + 70
    );
    assert(open_secure_rom_provisioning_extract_research_from_payload(
        &state,
        research
    ));
    assert(memcmp(&state.bytes[121], research + 1, 48) == 0);
    assert(state.bytes[169] == 1);
    assert(memcmp(&state.bytes[170], research + 50, 20) == 0);
    assert(state.bytes[190] == 1);
    research[85] ^= 1;
    assert(!open_secure_rom_provisioning_extract_research_from_payload(
        &state,
        research
    ));
}

static void test_runtime_decisions(void) {
    const int statuses[] = { 1, 1, 1 };
    assert(open_secure_rom_runtime_initialization_panic_reason(
        1, 1, 0, 0, NULL, 0) == 0x41);
    assert(open_secure_rom_runtime_initialization_panic_reason(
        0, 0, 0, 0, NULL, 0) == 0x47);
    assert(open_secure_rom_runtime_initialization_panic_reason(
        0, 1, 1, 0, NULL, 0) == 0x4c);
    assert(open_secure_rom_runtime_initialization_panic_reason(
        0, 1, 0, 4, statuses, 3) == 0);
    assert(open_secure_rom_runtime_initialization_panic_reason(
        0, 1, 0, 4, statuses, 2) == 0x50);
}

int main(void) {
    test_exception_layout_and_record();
    test_shared_region_copy_and_load();
    test_shared_region_payload_plan();
    test_provisioning_payloads();
    test_runtime_decisions();
    puts("system closure tests passed");
    return 0;
}
