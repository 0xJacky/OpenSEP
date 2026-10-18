#ifndef OPEN_SECURE_ROM_BOOT_HANDOFF_H
#define OPEN_SECURE_ROM_BOOT_HANDOFF_H

#include "open_secure_rom/types.h"

enum {
    SEP_BOOT_RUNTIME_HANDOFF_MAGIC = 0x53455042,
    SEP_BOOT_RUNTIME_HANDOFF_VERSION = 1,
    SEP_BOOT_RUNTIME_HANDOFF_SIZE = 224,
    SEP_BOOT_RUNTIME_HANDOFF_KEY_SIZE = 48,
    SEP_BOOT_RUNTIME_HANDOFF_PATTERN_SIZE = 64,
    SEP_BOOT_RUNTIME_HANDOFF_METADATA_SIZE = 28,
};

typedef struct sep_boot_runtime_handoff {
    sep_u32 magic;
    sep_u32 reserved_04;
    sep_u32 version;
    sep_u32 reserved_0c;
    sep_u32 header_size;
    sep_u32 reserved_14;
    sep_u64 runtime_destination;
    sep_u32 runtime_region_length;
    sep_u32 reserved_24;
    sep_u32 payload_type;
    sep_u32 reserved_2c;
    sep_u8 optional_key_present;
    sep_u8 reserved_31[7];
    sep_u8 optional_key[SEP_BOOT_RUNTIME_HANDOFF_KEY_SIZE];
    sep_u8 authorization_flag;
    sep_u8 reserved_69[7];
    sep_u32 payload_length;
    sep_u32 reserved_74;
    sep_u32 manifest_length;
    sep_u32 reserved_7c;
    sep_u8 research_pattern[SEP_BOOT_RUNTIME_HANDOFF_PATTERN_SIZE];
    sep_u8 platform_metadata[SEP_BOOT_RUNTIME_HANDOFF_METADATA_SIZE];
    sep_u8 reserved_dc[4];
} sep_boot_runtime_handoff_t;

_Static_assert(
    sizeof(sep_boot_runtime_handoff_t) == SEP_BOOT_RUNTIME_HANDOFF_SIZE,
    "runtime handoff size"
);
_Static_assert(offsetof(sep_boot_runtime_handoff_t, magic) == 0x00, "magic");
_Static_assert(offsetof(sep_boot_runtime_handoff_t, version) == 0x08, "version");
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, header_size) == 0x10,
    "header size"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, runtime_destination) == 0x18,
    "runtime destination"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, runtime_region_length) == 0x20,
    "runtime region length"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, payload_type) == 0x28,
    "payload type"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, optional_key_present) == 0x30,
    "optional key presence"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, optional_key) == 0x38,
    "optional key"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, authorization_flag) == 0x68,
    "authorization flag"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, payload_length) == 0x70,
    "payload length"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, manifest_length) == 0x78,
    "manifest length"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, research_pattern) == 0x80,
    "research pattern"
);
_Static_assert(
    offsetof(sep_boot_runtime_handoff_t, platform_metadata) == 0xc0,
    "platform metadata"
);

const sep_address_range_t *sep_boot_runtime_region_at(
    sep_size_t table_index
);
sep_size_t sep_boot_runtime_region_length(sep_size_t table_index);
sep_u64 sep_boot_runtime_destination_base(sep_u32 runtime_mode);

/* The registers the runtime is entered with. */
typedef struct {
    sep_u64 address;
    sep_u64 x0;
    sep_u64 x1;
    /* Written to s3_7_c15_c2_0 when non-zero. */
    sep_u64 power_down_save;
} sep_boot_runtime_entry_t;

sep_boot_runtime_entry_t sep_boot_runtime_entry(
    sep_u64 handoff_address,
    sep_u32 runtime_mode
);
sep_u64 sep_boot_build_runtime_handoff(
    const sep_shared_image_context_t *image,
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
);
void sep_boot_prepare_runtime_mapping(sep_u32 runtime_mode);
void __attribute__((noreturn))
sep_boot_prepare_runtime_mapping_and_panic_on_return(
    sep_u32 runtime_mode
);
void __attribute__((noreturn)) sep_early_runtime_halt_loop(void);
void sep_runtime_clear_regions(void);
void sep_runtime_copy_initialized_data(void);

/** Builds the recovered header into caller-owned storage for host validation. */
sep_u64 open_secure_rom_build_runtime_handoff_header(
    sep_boot_runtime_handoff_t *output,
    const sep_shared_image_context_t *image,
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
);

#ifdef OPEN_SECURE_ROM_HOST_TEST
void __attribute__((noreturn)) open_secure_rom_boot_handoff_test_panic(
    sep_u32 reason
);
#endif

#endif
