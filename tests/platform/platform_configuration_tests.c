#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

void sep_protocol_transition_noop_hook(void) {}

sep_size_t sep_runtime_region_table_length(sep_size_t table_index) {
    (void)table_index;
    return 0x02000000;
}

int main(void) {
    const sep_u8 block[16] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    sep_u8 output[16];

    sep_platform_configuration_initialize();

    sep_optional_configuration_key48_t key = {0};
    key.present = 1;
    for (sep_size_t index = 0; index < sizeof(key.bytes); ++index) {
        key.bytes[index] = (sep_u8)(index + 1);
    }
    sep_platform_configuration_write_optional_key48(
        &key,
        0x12345678,
        1
    );
    sep_u8 key_record[52];
    sep_platform_configuration_read(0x78, key_record, sizeof(key_record));
    for (sep_size_t index = 0; index < sizeof(key.bytes); ++index) {
        assert(key_record[index] == key.bytes[index]);
    }
    sep_u32 configuration_word;
    sep_memmove(
        &configuration_word,
        &key_record[48],
        sizeof(configuration_word)
    );
    assert(configuration_word == 0x12345678);
    assert(sep_platform_configuration_write_mode1_block0(
        block,
        sizeof(block)
    ) != 0);
    assert(sep_platform_configuration_read_mode1_block0(
        output,
        sizeof(output)
    ) == output);
    for (sep_size_t index = 0; index < sizeof(block); ++index) {
        assert(output[index] == block[index]);
    }

    sep_platform_configuration_write_runtime_feature_flags(0x12345678);
    assert(sep_platform_configuration_read_runtime_feature_flags() ==
        0x12345678);
    sep_platform_configuration_seed_research_block();
    sep_u8 research_block[24];
    sep_platform_configuration_read(
        0x108,
        research_block,
        sizeof(research_block)
    );
    const sep_u8 pattern[4] = {0xef, 0xbe, 0xad, 0xde};
    for (sep_size_t index = 0; index < sizeof(research_block); ++index) {
        assert(research_block[index] == pattern[index & 3]);
    }
    sep_platform_seed_runtime_mode_configuration_blocks(1);
    sep_platform_validate_runtime_mode_configuration_blocks(1);
    sep_platform_seed_runtime_mode_configuration_blocks(4);
    sep_platform_validate_runtime_mode_configuration_blocks(4);
    sep_platform_publish_runtime_region_size_kib();
    assert(sep_platform_read_runtime_region_size_kib() == 0x8000);
}
