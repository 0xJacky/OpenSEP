#include "open_secure_rom/boot_handoff.h"

#include "open_secure_rom/boot_platform.h"
#include "open_secure_rom/runtime.h"

#include <assert.h>
#include <setjmp.h>

static sep_address_range_t runtime_regions[8];
static sep_u8 metadata[SEP_BOOT_RUNTIME_HANDOFF_METADATA_SIZE];
static sep_bool emit_zero_pattern;
static volatile sep_u32 panic_reason;
static jmp_buf panic_jump;

void __attribute__((noreturn)) open_secure_rom_boot_handoff_test_panic(
    sep_u32 reason
) {
    panic_reason = reason;
    longjmp(panic_jump, 1);
}

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected generic fatal path");
    __builtin_unreachable();
}

const sep_address_range_t *sep_runtime_region_at_checked(
    sep_u32 region_index
) {
    assert(region_index < 8);
    return &runtime_regions[region_index];
}

sep_size_t sep_address_range_length(const sep_address_range_t *range) {
    assert(range->end >= range->start);
    return (sep_size_t)(range->end - range->start);
}

sep_u64 sep_runtime_mode_region_offset(sep_u32 runtime_mode) {
    static const sep_u64 offsets[6] = {
        0,
        0,
        0,
        0x06000000,
        0,
        0x06000000,
    };
    assert(runtime_mode >= 1 && runtime_mode <= 6);
    return offsets[runtime_mode - 1];
}

sep_u64 sep_runtime_region_mode_base(
    sep_u32 region_index,
    sep_u32 runtime_mode
) {
    return sep_runtime_region_at_checked(region_index)->start +
        sep_runtime_mode_region_offset(runtime_mode);
}

sep_u32 sep_shared_image_context_payload_type_checked(
    const sep_shared_image_context_t *context
) {
    sep_u32 value;
    sep_memmove(&value, &context->decoded_properties[4], sizeof(value));
    assert(value != 0);
    return value;
}

sep_optional_configuration_key48_t
sep_shared_image_context_get_optional_key48(
    const sep_shared_image_context_t *context
) {
    sep_optional_configuration_key48_t result;
    sep_memmove(
        result.bytes,
        &context->decoded_properties[57],
        sizeof(result.bytes)
    );
    result.present = context->decoded_properties[105];
    return result;
}

sep_u8 sep_shared_image_context_mode_checked(
    const sep_shared_image_context_t *context
) {
    return context->decoded_properties[0];
}

sep_bool sep_shared_image_properties_amnm_checked(
    const sep_shared_image_properties_t *properties
) {
    return properties->bytes[241];
}

void *sep_fill_research_seed_pattern(void *buffer, sep_size_t length) {
    static const sep_u8 pattern[4] = {0xef, 0xbe, 0xad, 0xde};
    sep_u8 *bytes = buffer;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = emit_zero_pattern ? 0 : pattern[index & 3];
    }
    return buffer;
}

void sep_platform_copy_runtime_handoff_metadata(
    void *output,
    sep_size_t output_length
) {
    assert(output_length == sizeof(metadata));
    sep_memmove(output, metadata, sizeof(metadata));
}

static void store_u32(sep_u8 *output, sep_size_t offset, sep_u32 value) {
    output[offset] = (sep_u8)value;
    output[offset + 1] = (sep_u8)(value >> 8);
    output[offset + 2] = (sep_u8)(value >> 16);
    output[offset + 3] = (sep_u8)(value >> 24);
}

static void store_u64(sep_u8 *output, sep_size_t offset, sep_u64 value) {
    for (sep_size_t index = 0; index < 8; ++index) {
        output[offset + index] = (sep_u8)(value >> (index * 8));
    }
}

static void initialize_context(
    sep_shared_image_context_t *context,
    sep_u8 image_mode,
    sep_u32 payload_type
) {
    sep_memzero(context, sizeof(*context));
    context->decoded_properties[0] = image_mode;
    sep_memmove(
        &context->decoded_properties[4],
        &payload_type,
        sizeof(payload_type)
    );
}

static void initialize_regions(void) {
    sep_memzero(runtime_regions, sizeof(runtime_regions));
    runtime_regions[1] = (sep_address_range_t){
        .start = 0x00100000,
        .end = 0x02100000,
    };
    runtime_regions[2] = (sep_address_range_t){
        .start = 0,
        .end = 0x02000000,
    };
    runtime_regions[3] = runtime_regions[2];
}

#define EXPECT_BOOT_PANIC(statement, expected_reason) \
    do { \
        panic_reason = 0; \
        if (setjmp(panic_jump) == 0) { \
            statement; \
            assert(0 && "expected boot handoff panic"); \
        } \
        assert(panic_reason == (expected_reason)); \
    } while (0)

static void test_region_accessors(void) {
    open_secure_rom_boot_platform_test_select(SEP_BOOT_PLATFORM_T8110);
    initialize_regions();
    assert(sep_boot_runtime_region_at(1) == &runtime_regions[1]);
    assert(sep_boot_runtime_region_length(1) == 0x02000000);
    /*
     * On t8110 the destination is the runtime's address in the SEP's own
     * view, fixed at 0x3_4000_0000; moving region 1 changes nothing.
     */
    assert(sep_boot_runtime_destination_base(4) == 0x340000000ULL);
    runtime_regions[1].start = UINT64_MAX - 0x05ffffff;
    assert(sep_boot_runtime_destination_base(4) == 0x340000000ULL);
    initialize_regions();
    EXPECT_BOOT_PANIC(
        (void)sep_boot_runtime_region_at((sep_size_t)UINT32_MAX + 1),
        0x2f
    );
}

static void test_golden_header(void) {
    open_secure_rom_boot_platform_test_select(SEP_BOOT_PLATFORM_T8110);
    initialize_regions();
    for (sep_size_t index = 0; index < sizeof(metadata); ++index) {
        metadata[index] = (sep_u8)index;
    }
    emit_zero_pattern = 0;

    sep_shared_image_context_t context;
    initialize_context(&context, 0, 0x73657072);
    sep_boot_runtime_handoff_t handoff;
    const sep_u64 address = open_secure_rom_build_runtime_handoff_header(
        &handoff,
        &context,
        0x41,
        0x3f,
        4
    );
    assert(address == 0x340000080ULL);

    sep_u8 expected[SEP_BOOT_RUNTIME_HANDOFF_SIZE] = {0};
    store_u32(expected, 0x00, SEP_BOOT_RUNTIME_HANDOFF_MAGIC);
    store_u32(expected, 0x08, SEP_BOOT_RUNTIME_HANDOFF_VERSION);
    store_u32(expected, 0x10, SEP_BOOT_RUNTIME_HANDOFF_SIZE);
    store_u64(expected, 0x18, 0x340000000ULL);
    store_u32(expected, 0x20, 0x08000000);
    store_u32(expected, 0x28, 0x73657072);
    store_u32(expected, 0x70, 0x41);
    store_u32(expected, 0x78, 0x3f);
    for (sep_size_t index = 0; index < 64; ++index) {
        static const sep_u8 pattern[4] = {0xef, 0xbe, 0xad, 0xde};
        expected[0x80 + index] = pattern[index & 3];
    }
    for (sep_size_t index = 0; index < sizeof(metadata); ++index) {
        expected[0xc0 + index] = (sep_u8)index;
    }
    const sep_u8 *actual = (const sep_u8 *)&handoff;
    for (sep_size_t index = 0; index < sizeof(expected); ++index) {
        assert(actual[index] == expected[index]);
    }
}

static sep_u8 build_key_policy_header(
    sep_u8 image_mode,
    sep_bool amnm
) {
    initialize_regions();
    sep_shared_image_context_t context;
    initialize_context(&context, image_mode, 0x73657072);
    for (sep_size_t index = 0; index < 48; ++index) {
        context.decoded_properties[57 + index] = (sep_u8)(0x80 + index);
    }
    context.decoded_properties[105] = 1;
    context.decoded_properties[241] = amnm;

    sep_boot_runtime_handoff_t handoff;
    (void)open_secure_rom_build_runtime_handoff_header(
        &handoff,
        &context,
        0,
        0,
        4
    );
    assert(handoff.optional_key_present == 1);
    for (sep_size_t index = 0; index < 48; ++index) {
        assert(handoff.optional_key[index] == (sep_u8)(0x80 + index));
    }
    return handoff.authorization_flag;
}

static void test_key_policy(void) {
    assert(build_key_policy_header(1, 0) == 1);
    assert(build_key_policy_header(0, 0) == 1);
    assert(build_key_policy_header(0, 1) == 0);

    initialize_regions();
    sep_shared_image_context_t context;
    initialize_context(&context, 4, 0x73657072);
    context.decoded_properties[105] = 1;
    sep_boot_runtime_handoff_t handoff;
    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            0,
            0,
            4
        ),
        0x84
    );
}

static void test_capacity_boundary(void) {
    open_secure_rom_boot_platform_test_select(SEP_BOOT_PLATFORM_T8110);
    initialize_regions();
    runtime_regions[1] = (sep_address_range_t){
        .start = 0,
        .end = 0x1020,
    };
    sep_shared_image_context_t context;
    initialize_context(&context, 0, 0x73657072);
    sep_boot_runtime_handoff_t handoff;

    assert(open_secure_rom_build_runtime_handoff_header(
        &handoff,
        &context,
        0xf40,
        0,
        4
    ) == 0x340000f40ULL);
    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            0xf41,
            0,
            4
        ),
        0x53
    );
}

static void test_checked_arithmetic(void) {
    initialize_regions();
    sep_shared_image_context_t context;
    initialize_context(&context, 0, 0x73657072);
    sep_boot_runtime_handoff_t handoff;

    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            SIZE_MAX,
            1,
            4
        ),
        0x1c
    );
    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            0x02000000,
            0,
            4
        ),
        0x53
    );
    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            0,
            0,
            2
        ),
        0x49
    );

    runtime_regions[1].end = runtime_regions[1].start + UINT32_MAX;
    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            0,
            0,
            4
        ),
        0x3b
    );

    initialize_regions();
    emit_zero_pattern = 1;
    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            0,
            0,
            4
        ),
        0x92
    );
    emit_zero_pattern = 0;

    EXPECT_BOOT_PANIC(
        (void)open_secure_rom_build_runtime_handoff_header(
            &handoff,
            &context,
            0,
            0,
            1
        ),
        0x9b
    );
}

/*
 * AVPSEPBooter.vresearch1's rule: enter at region one's base plus the mode's
 * offset, and cap runtime_region_length at 0x18000.
 */
static void test_vresearch1_header(void) {
    open_secure_rom_boot_platform_test_select(SEP_BOOT_PLATFORM_VRESEARCH1);
    initialize_regions();
    assert(sep_boot_runtime_destination_base(4) == 0x06100000ULL);

    sep_shared_image_context_t context;
    initialize_context(&context, 0, 0x73657072);
    sep_boot_runtime_handoff_t handoff;
    assert(open_secure_rom_build_runtime_handoff_header(
        &handoff,
        &context,
        0x41,
        0x3f,
        4
    ) == 0x06100080ULL);
    assert(handoff.runtime_destination == 0x06100000ULL);
    assert(handoff.runtime_region_length == 0x18000);

    runtime_regions[1].end = runtime_regions[1].start + 0x1020;
    (void)open_secure_rom_build_runtime_handoff_header(
        &handoff,
        &context,
        0x40,
        0,
        4
    );
    assert(handoff.runtime_region_length == 0x1020);
}

static void test_runtime_entry(void) {
    initialize_regions();

    open_secure_rom_boot_platform_test_select(SEP_BOOT_PLATFORM_VRESEARCH1);
    sep_boot_runtime_entry_t entry = sep_boot_runtime_entry(0x06100080, 4);
    assert(entry.address == 0x06100000ULL);
    assert(entry.x0 == 0x06100080ULL);
    assert(entry.x1 == 0);
    assert(entry.power_down_save == 0);

    open_secure_rom_boot_platform_test_select(SEP_BOOT_PLATFORM_T8110);
    entry = sep_boot_runtime_entry(0x340000080, 4);
    assert(entry.address == 0x340000000ULL);
    assert(entry.x0 == 0x340000081ULL);
    assert(entry.x1 == 0x340680000ULL);
    assert(entry.power_down_save == 0x340000081ULL);
}

int main(void) {
    test_region_accessors();
    test_golden_header();
    test_vresearch1_header();
    test_runtime_entry();
    test_key_policy();
    test_capacity_boundary();
    test_checked_arithmetic();
}
