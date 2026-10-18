#ifndef OPEN_SECURE_ROM_TYPES_H
#define OPEN_SECURE_ROM_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t sep_bool;
typedef uint8_t sep_u8;
typedef uint16_t sep_u16;
typedef uint32_t sep_u32;
typedef uint64_t sep_u64;
typedef size_t sep_size_t;

#ifdef OPEN_SECURE_ROM_HOST_TEST
#define OPEN_SECURE_ROM_SECTION(name)
#else
#define OPEN_SECURE_ROM_SECTION(name) __attribute__((section(name)))
#endif

typedef struct sep_address_range {
    sep_u64 start;
    sep_u64 end;
} sep_address_range_t;

typedef struct sep_checked_bytes20 {
    sep_u8 bytes[20];
    sep_bool initialized;
} sep_checked_bytes20_t;

typedef struct sep_checked_bytes48 {
    sep_u8 bytes[48];
    sep_bool initialized;
} sep_checked_bytes48_t;

typedef struct sep_checked_bytes32 {
    sep_u8 bytes[32];
    sep_bool initialized;
} sep_checked_bytes32_t;

typedef struct sep_runtime_feature_flags {
    sep_bool valid;
    sep_bool flags[8];
} sep_runtime_feature_flags_t;

typedef struct sep_optional_u8 {
    sep_bool present;
    sep_u8 value;
} sep_optional_u8_t;

typedef struct sep_optional_u16 {
    sep_bool present;
    sep_u8 reserved;
    sep_u16 value;
} sep_optional_u16_t;

typedef struct sep_optional_u64 {
    sep_bool present;
    sep_u8 reserved[7];
    sep_u64 value;
} sep_optional_u64_t;

typedef struct sep_optional_bool {
    sep_bool present;
    sep_bool value;
} sep_optional_bool_t;

typedef struct sep_shared_image_properties {
    sep_u8 bytes[264];
} __attribute__((aligned(8))) sep_shared_image_properties_t;

typedef struct sep_shared_image_context {
    sep_u8 decoded_properties[264];
    const void *payload_data;
    sep_size_t payload_size;
    const void *manifest_data;
    sep_size_t manifest_size;
    sep_u8 auxiliary[172];
    sep_u8 trailing[4];
} sep_shared_image_context_t;

typedef struct sep_shared_image_auxiliary_keybag_entry {
    sep_bool present;
    sep_u8 reserved[3];
    sep_u32 key_bit_length;
    sep_u8 metadata[16];
    sep_u8 key[32];
} sep_shared_image_auxiliary_keybag_entry_t;

typedef sep_shared_image_auxiliary_keybag_entry_t
    sep_shared_image_payload_keybag_t;

typedef struct sep_shared_image_auxiliary {
    sep_bool present;
    sep_u8 reserved[3];
    sep_shared_image_auxiliary_keybag_entry_t entries[3];
} sep_shared_image_auxiliary_t;

typedef sep_u32 sep_shared_image_research_policy_t;

typedef struct sep_platform_provisioning_state {
    sep_u8 bytes[388];
} sep_platform_provisioning_state_t;

typedef struct sep_cc_ws {
    sep_u64 *ctx;
    sep_size_t nunits;
    sep_size_t offset;
} sep_cc_ws_t;

typedef struct sep_ccdigest_info sep_ccdigest_info_t;
typedef struct sep_ccdigest_ctx sep_ccdigest_ctx_t;
typedef struct sep_cchmac_ctx sep_cchmac_ctx_t;

typedef struct sep_cczp {
    sep_size_t n;
    sep_u64 bitlen;
    const void *funcs;
} sep_cczp_t;

_Static_assert(
    sizeof(sep_platform_provisioning_state_t) == 388,
    "provisioning state ABI"
);

_Static_assert(sizeof(sep_shared_image_properties_t) == 264, "properties ABI");
_Static_assert(sizeof(sep_shared_image_context_t) == 472, "context ABI");
_Static_assert(sizeof(sep_shared_image_payload_keybag_t) == 56, "keybag ABI");
_Static_assert(sizeof(sep_shared_image_auxiliary_t) == 172, "auxiliary ABI");

typedef struct sep_mailbox_slot {
    sep_u64 low;
    sep_u64 high;
} sep_mailbox_slot_t;

#pragma pack(push, 1)
typedef struct sep_optional_research_seed {
    sep_u8 bytes[20];
    sep_u8 present;
} sep_optional_research_seed_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct sep_optional_research_value64 {
    sep_u64 value;
    sep_u8 present;
} sep_optional_research_value64_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct sep_optional_configuration_key48 {
    sep_u8 bytes[48];
    sep_u8 present;
} sep_optional_configuration_key48_t;
#pragma pack(pop)

#endif
