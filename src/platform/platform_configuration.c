#include "open_secure_rom/platform.h"

#include "open_secure_rom/configuration_sink.h"
#include "open_secure_rom/mailbox.h"
#include "open_secure_rom/protocol.h"
#include "open_secure_rom/runtime.h"
#include "open_secure_rom/runtime_storage.h"

enum {
    SEP_PLATFORM_CONFIGURATION_SIZE = 384,
    SEP_PLATFORM_CONFIGURATION_BLOCK_SIZE = 16,
};

static sep_bool platform_configuration_initialized
    OPEN_SECURE_ROM_SECTION(".platform_configuration_initialized");
static sep_u8 platform_configuration[SEP_PLATFORM_CONFIGURATION_SIZE]
    OPEN_SECURE_ROM_SECTION(".platform_configuration");

static void open_secure_rom_require_platform_configuration(void) {
    if (!platform_configuration_initialized) {
        sep_fatal_wait_loop();
    }
}

static void open_secure_rom_require_configuration_block_length(
    sep_size_t length
) {
    open_secure_rom_require_platform_configuration();
    if (length != SEP_PLATFORM_CONFIGURATION_BLOCK_SIZE) {
        sep_fatal_wait_loop();
    }
}

void sep_platform_configuration_initialize(void) {
    if (platform_configuration_initialized) {
        sep_fatal_wait_loop();
    }
    sep_memzero(platform_configuration, sizeof(platform_configuration));
    platform_configuration_initialized = 1;
}

void sep_platform_configuration_seed_research_block(void) {
    open_secure_rom_require_platform_configuration();
    sep_u8 block[24];
    sep_fill_research_seed_pattern(block, sizeof(block));
    sep_platform_configuration_write(0x108, block, sizeof(block));
}

void sep_platform_configuration_write_optional_key48(
    const sep_optional_configuration_key48_t *key,
    sep_u32 configuration_word,
    sep_bool include_key
) {
    sep_u8 record[52];
    sep_memzero(record, sizeof(record));
    const sep_bool key_present = sep_optional_configuration_key48_is_present(key);
    if (include_key && key_present) {
        sep_memmove(record, key->bytes, sizeof(key->bytes));
    }
    sep_memmove(&record[48], &configuration_word, sizeof(configuration_word));
    sep_platform_configuration_write(0x78, record, sizeof(record));
}

void *sep_platform_configuration_write(
    sep_size_t offset,
    const void *source,
    sep_size_t length
) {
    if (length > sizeof(platform_configuration) ||
        offset > sizeof(platform_configuration) - length || source == 0) {
        sep_fatal_wait_loop();
    }
    return sep_memmove(platform_configuration + offset, source, length);
}

void *sep_platform_configuration_read(
    sep_size_t offset,
    void *destination,
    sep_size_t length
) {
    if (length > sizeof(platform_configuration) ||
        offset > sizeof(platform_configuration) - length || destination == 0) {
        sep_fatal_wait_loop();
    }
    return sep_memmove(destination, platform_configuration + offset, length);
}

void *sep_platform_configuration_write_mode1_block0(
    const void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_write(0x10, block, length);
}

void *sep_platform_configuration_write_mode1_block1(
    const void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_write(0x20, block, length);
}

void *sep_platform_configuration_read_mode1_block0(
    void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_read(0x10, block, length);
}

void *sep_platform_configuration_read_mode1_block1(
    void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_read(0x20, block, length);
}

void *sep_platform_configuration_write_mode4_block0(
    const void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_write(0x48, block, length);
}

void *sep_platform_configuration_write_mode4_block1(
    const void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_write(0x58, block, length);
}

void *sep_platform_configuration_read_mode4_block0(
    void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_read(0x48, block, length);
}

void *sep_platform_configuration_read_mode4_block1(
    void *block,
    sep_size_t length
) {
    open_secure_rom_require_configuration_block_length(length);
    return sep_platform_configuration_read(0x58, block, length);
}

sep_u32 sep_platform_configuration_read_runtime_feature_flags(void) {
    open_secure_rom_require_platform_configuration();
    sep_u32 flags = 0;
    sep_platform_configuration_read(0x30, &flags, sizeof(flags));
    return flags;
}

void *sep_platform_configuration_write_runtime_feature_flags(
    sep_u32 packed_flags
) {
    open_secure_rom_require_platform_configuration();
    return sep_platform_configuration_write(
        0x30,
        &packed_flags,
        sizeof(packed_flags)
    );
}

sep_u32 sep_platform_read_runtime_region_size_kib(void) {
    sep_u32 size_kib = 0;
    sep_platform_configuration_read(0x34, &size_kib, sizeof(size_kib));
    return size_kib;
}

void sep_platform_publish_runtime_region_size_kib(void) {
    const sep_u32 size_kib = (sep_u32)(
        sep_runtime_region_table_length(2) >> 10
    );
    sep_platform_configuration_write(0x34, &size_kib, sizeof(size_kib));
}

void sep_platform_seed_runtime_mode_configuration_blocks(
    sep_u32 runtime_mode
) {
    sep_u8 block[SEP_PLATFORM_CONFIGURATION_BLOCK_SIZE];
    sep_fill_research_seed_pattern(block, sizeof(block));
    if (!sep_buffer_has_nonzero_byte(block, sizeof(block))) {
        sep_fatal_wait_loop();
    }

    if (runtime_mode == 1) {
        sep_platform_configuration_write_mode1_block0(block, sizeof(block));
        sep_platform_mode1_configuration_noop(block, sizeof(block), 0);
        sep_protocol_transition_noop_hook();
        sep_fill_research_seed_pattern(block, sizeof(block));
        sep_platform_configuration_write_mode1_block1(block, sizeof(block));
        sep_platform_mode4_configuration_noop(block, sizeof(block), 2);
        sep_protocol_transition_noop_hook();
    } else if (runtime_mode == 4) {
        sep_platform_configuration_write_mode4_block0(block, sizeof(block));
        sep_platform_mode1_configuration_noop(block, sizeof(block), 1);
        sep_protocol_transition_noop_hook();
        sep_platform_mode4_block0_optional_hook();
        sep_fill_research_seed_pattern(block, sizeof(block));
        sep_platform_configuration_write_mode4_block1(block, sizeof(block));
        sep_platform_mode4_configuration_noop(block, sizeof(block), 3);
        sep_protocol_transition_noop_hook();
        sep_platform_mode4_block1_optional_hook();
    } else {
        sep_fatal_wait_loop();
    }
#ifndef OPEN_SECURE_ROM_HOST_TEST
    __asm__ volatile("dsb sy" ::: "memory");
#endif
}

void sep_platform_validate_runtime_mode_configuration_blocks(
    sep_u32 runtime_mode
) {
    sep_u8 block[SEP_PLATFORM_CONFIGURATION_BLOCK_SIZE];
    if (runtime_mode == 1) {
        sep_platform_configuration_read_mode1_block0(block, sizeof(block));
        if (!sep_buffer_has_nonzero_byte(block, sizeof(block))) {
            sep_fatal_wait_loop();
        }
        sep_platform_mode1_configuration_noop(block, sizeof(block), 0);
        sep_protocol_transition_noop_hook();
        sep_platform_configuration_read_mode1_block1(block, sizeof(block));
        if (!sep_buffer_has_nonzero_byte(block, sizeof(block))) {
            sep_fatal_wait_loop();
        }
        sep_platform_mode4_configuration_noop(block, sizeof(block), 2);
        sep_protocol_transition_noop_hook();
    } else if (runtime_mode == 4) {
        sep_platform_configuration_read_mode4_block0(block, sizeof(block));
        if (!sep_buffer_has_nonzero_byte(block, sizeof(block))) {
            sep_fatal_wait_loop();
        }
        sep_platform_mode1_configuration_noop(block, sizeof(block), 1);
        sep_protocol_transition_noop_hook();
        if (sep_platform_runtime_configuration_hook_enabled(0)) {
            sep_platform_mode4_block0_optional_hook();
        }
        sep_platform_configuration_read_mode4_block1(block, sizeof(block));
        if (!sep_buffer_has_nonzero_byte(block, sizeof(block))) {
            sep_fatal_wait_loop();
        }
        sep_platform_mode4_configuration_noop(block, sizeof(block), 3);
        sep_protocol_transition_noop_hook();
        if (sep_platform_runtime_configuration_hook_enabled(1)) {
            sep_platform_mode4_block1_optional_hook();
        }
    } else {
        sep_fatal_wait_loop();
    }
#ifndef OPEN_SECURE_ROM_HOST_TEST
    __asm__ volatile("dsb sy" ::: "memory");
#endif
}
