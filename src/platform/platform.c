#include "open_secure_rom/platform.h"

#include "open_secure_rom/runtime.h"

sep_u32 sep_platform_capability_mask_zero_stub(sep_u32 capability_id) {
    (void)capability_id;
    return 0;
}

sep_u32 sep_platform_required_capability_mask_zero_stub(void) {
    return 0;
}

void sep_platform_key_service_finalize_noop(sep_u32 capability_mask) {
    (void)capability_mask;
}

void sep_platform_runtime_feature_commit_noop(
    sep_u32 feature_id,
    sep_bool enabled
) {
    (void)feature_id;
    (void)enabled;
}

sep_bool sep_platform_required_feature_supported_stub(sep_u32 feature_id) {
    (void)feature_id;
    return 1;
}

void sep_platform_transition_noop_hook(sep_u32 feature_id, sep_bool enabled) {
    (void)feature_id;
    (void)enabled;
}

sep_bool sep_platform_optional_feature_supported_zero_stub(sep_u32 feature_id) {
    (void)feature_id;
    return 0;
}

sep_bool sep_platform_payload_keybag_selector_zero_stub(
    void *output,
    const void *input,
    sep_size_t input_length,
    const sep_u8 iv[16],
    sep_size_t key_bit_length
) {
    (void)output;
    (void)input;
    (void)input_length;
    (void)iv;
    (void)key_bit_length;
    return 0;
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

void sep_platform_runtime_feature_preapply_noop(void) {}

void sep_platform_runtime_feature_postapply_noop(sep_u32 feature_id) {
    (void)feature_id;
}

sep_bool sep_platform_payload_keybag_policy_zero_stub(sep_u32 policy_id) {
    (void)policy_id;
    return 0;
}

void sep_platform_panic_record_prepare_noop(
    const void *constant,
    sep_size_t bit_length
) {
    (void)constant;
    (void)bit_length;
}

void sep_platform_wrak_autk_install_begin_noop(
    const sep_u8 material[28],
    sep_size_t material_length,
    sep_u32 selector,
    const char *label
) {
    (void)material;
    (void)material_length;
    (void)selector;
    (void)label;
}

void sep_platform_wrak_autk_invalid_selector_noop(sep_u32 selector) {
    (void)selector;
}

void sep_platform_wrak_autk_valid_selector_noop(sep_u32 selector) {
    (void)selector;
}

void sep_platform_wrak_autk_derivation_begin_noop(
    sep_u32 selector,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
) {
    (void)selector;
    (void)source;
    (void)source_length;
    (void)output;
    (void)output_length;
}

void sep_platform_wrak_autk_derivation_end_noop(
    sep_u32 selector,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
) {
    (void)selector;
    (void)source;
    (void)source_length;
    (void)output;
    (void)output_length;
}

void sep_platform_autp_install_begin_noop(
    const sep_u8 material[28],
    sep_size_t material_length,
    sep_u32 selector,
    const char *label
) {
    (void)material;
    (void)material_length;
    (void)selector;
    (void)label;
}

void sep_platform_mode1_configuration_noop(
    const void *configuration,
    sep_size_t configuration_length,
    sep_u32 slot
) {
    (void)configuration;
    (void)configuration_length;
    (void)slot;
}

void sep_platform_mode4_configuration_noop(
    const void *configuration,
    sep_size_t configuration_length,
    sep_u32 slot
) {
    (void)configuration;
    (void)configuration_length;
    (void)slot;
}

void sep_platform_configuration_alternate_init_noop(void) {}

void sep_platform_runtime_authentication_finalize_noop(void) {}

void sep_platform_runtime_region_prepare_noop(sep_u32 runtime_mode) {
    (void)runtime_mode;
}

void sep_platform_identity_initialize(void) {}

#ifdef OPEN_SECURE_ROM_HOST_TEST
/*
 * The register window, on a host that cannot place anything at 0x30400000:
 * macOS on arm64 keeps __PAGEZERO over the whole low four gigabytes.  The
 * machine answers this window inert, so zeroes are what the part reads.
 */
static sep_u32 host_platform_registers[0x1000 / sizeof(sep_u32)];

sep_u32 *open_secure_rom_host_platform_registers(void) {
    return host_platform_registers;
}
#endif

static volatile sep_u32 *open_secure_rom_platform_register(sep_size_t offset) {
#ifdef OPEN_SECURE_ROM_HOST_TEST
    return (volatile sep_u32 *)((sep_u8 *)host_platform_registers + offset);
#else
    return (volatile sep_u32 *)(0x30400000ULL + offset);
#endif
}

sep_u32 sep_platform_read_flag_0c_encoded(void) {
    return (*open_secure_rom_platform_register(0x0c) != 0 ? 0x100U : 0) | 1U;
}

sep_u32 sep_platform_read_flag_08_encoded(void) {
    return (*open_secure_rom_platform_register(0x08) != 0 ? 0x100U : 0) | 1U;
}

sep_u32 sep_platform_read_flag_08_boolean_encoded(void) {
    return sep_platform_read_flag_08_encoded();
}

sep_u32 sep_platform_read_flag_0c_boolean_encoded(void) {
    return sep_platform_read_flag_0c_encoded();
}

sep_u32 sep_platform_get_security_epoch(void) {
    return 0;
}

sep_u32 sep_platform_get_chip_id(void) {
    return 0xfe01;
}

sep_u64 sep_platform_read_ecid(void) {
    const sep_u32 high = *open_secure_rom_platform_register(0x1c);
    const sep_u32 low = *open_secure_rom_platform_register(0x18);
    return low | ((sep_u64)high << 32);
}

sep_u64 sep_platform_get_panic_context_word(void) {
    return 0;
}

sep_u32 sep_platform_read_chip_revision(void) {
    return *open_secure_rom_platform_register(0x10);
}

sep_u32 sep_platform_read_security_domain_encoded(void) {
    return (*open_secure_rom_platform_register(0x2c) << 8) | 1U;
}

sep_bool sep_platform_diagnostic_disclosure_enabled(void) {
    return 0;
}

sep_bool sep_platform_primary_runtime_path_enabled(void) {
    return 1;
}

sep_bool sep_platform_secondary_runtime_path_enabled(void) {
    return 1;
}

int sep_platform_runtime_iteration_status(sep_u8 slot_index) {
    (void)slot_index;
    return 0;
}

sep_bool sep_platform_feature_gate(void) {
    return 0;
}

/*
 * The SEP firmware keys this part knows.
 *
 * On silicon the payload key is unwrapped from the image's keybag with the
 * GID, and there is no GID here.  What the part does have is the key itself,
 * outright -- which is the same statement the hardware makes one step later.
 *
 * There is more than one, because there is more than one firmware: the key is
 * per image, not per part, and nothing in the image names which one it is.
 * So the table is enumerated and the right entry is found by trial decryption
 * of the payload's first block -- see
 * `sep_shared_image_select_payload_keybag_for_payload`.  Adding a build means
 * adding a row here and nothing else.
 *
 * Every row is a publicly published key: the SEPFirmwareIV and SEPFirmwareKey
 * of each build's sep-firmware.d16.RELEASE.im4p as listed on The Apple Wiki,
 * <https://theapplewiki.com/wiki/Keys:<Codename>_<build>_(iPhone14,4)>.
 * Rows are in table order (the index is reported in the event log, so a new
 * build is appended, never inserted):
 *
 *   0  21A329  iOS 17.0    Keys:Dawn_21A329_(iPhone14,4)
 *   1  19A348  iOS 15.0.1  Keys:Sky_19A348_(iPhone14,4)
 *   2  24A437  iOS 27.0    Keys:Rave_24A437_(iPhone14,4)
 *   3  20A362  iOS 16.0    Keys:Sydney_20A362_(iPhone14,4)
 *   4  23A341  iOS 26.0    Keys:Luck_23A341_(iPhone14,4)
 *   5  22G100  iOS 18.6.2  Keys:CrystalG_22G100_(iPhone14,4)
 *
 * Each row was checked byte for byte against its wiki page on 2026-10-18.
 * A future version may take the key from the host instead of carrying this
 * table.
 *
 * Notes per build:
 *
 *   21A329 (iPhone14,4)  sep-firmware.d16.RELEASE.im4p, no keybag in the image
 *   19A348 (iPhone14,4)  sep-firmware.d16.RELEASE.im4p, keybag present but
 *                        still wrapped, so it is of no use to us
 *   24A437 (iPhone14,4)  sep-firmware.d16.RELEASE.im4p, two keybags in the
 *                        image (PRODUCTION and DEVELOPMENT), both wrapped.
 *                        Verified 2026-09-24 by decrypting the payload with
 *                        this row: it yields the reset prologue the selection
 *                        looks for, `01 00 00 10 e2 3f 00 10 02 c0 18 d5`,
 *                        followed by `fd 0f 00 14` -- a third value for the
 *                        branch word, which is why only twelve bytes are
 *                        compared.
 *   20A362 (iPhone14,4)  sep-firmware.d16.RELEASE.im4p (iOS 16.0), key from
 *                        the wiki's SEPFirmware row.  Verified 2026-10-14 the
 *                        same way: `01 00 00 10 e2 3f 00 10 02 c0 18 d5`,
 *                        then `fd 0f 00 14`.
 *   23A341 (iPhone14,4)  sep-firmware.d16.RELEASE.im4p, PRODUCTION and
 *                        DEVELOPMENT keybags, both wrapped; the row is the
 *                        published key, appended last so every earlier
 *                        build still matches on the row it always did.
 */
typedef struct {
    sep_u8 iv[16];
    sep_u8 key[32];
} platform_firmware_key_t;

static const platform_firmware_key_t platform_firmware_keys[] = {
    {
        {
            0x0d, 0x32, 0x53, 0x8e, 0xe4, 0xe3, 0xdb, 0x8d,
            0x95, 0xb0, 0x3a, 0x4a, 0xc2, 0xed, 0xe2, 0xb8,
        },
        {
            0x0b, 0x34, 0xc9, 0xf8, 0x2a, 0xa1, 0x00, 0x35,
            0x52, 0x3a, 0xc2, 0xdb, 0x25, 0xb7, 0xcb, 0x22,
            0x0b, 0xc5, 0xfb, 0x7d, 0xdc, 0x4e, 0x24, 0x5b,
            0x95, 0x29, 0xaa, 0x07, 0xd0, 0xea, 0x6b, 0x4d,
        },
    },
    {
        {
            0xae, 0xc2, 0x8b, 0xaa, 0x74, 0xb4, 0x40, 0xe7,
            0xf5, 0xaf, 0x7c, 0x38, 0x42, 0x84, 0x33, 0x62,
        },
        {
            0xdc, 0xdc, 0x7b, 0xcb, 0xe4, 0x9e, 0xa9, 0xbf,
            0xfa, 0x87, 0x62, 0x9e, 0xa9, 0x34, 0x5a, 0xc5,
            0x11, 0x77, 0x85, 0x78, 0xfe, 0x4e, 0x5c, 0x37,
            0xb4, 0x58, 0x13, 0xd0, 0xc9, 0x2e, 0x03, 0xf0,
        },
    },
    {
        {
            0x9a, 0xad, 0xfd, 0xa7, 0x99, 0xec, 0x8a, 0x29,
            0x74, 0x41, 0x27, 0x65, 0xe0, 0xb2, 0xc3, 0xd7,
        },
        {
            0x3b, 0x78, 0x8e, 0xa2, 0xfa, 0xe9, 0xf5, 0x44,
            0xb6, 0x48, 0x7f, 0xda, 0xfc, 0x18, 0x73, 0x14,
            0xe1, 0x63, 0xef, 0xdf, 0x7e, 0x94, 0xac, 0xa3,
            0x18, 0xa4, 0xca, 0xa9, 0xfc, 0x1f, 0x46, 0x59,
        },
    },
    {
        /* 20A362 (iOS 16.0): appended last, so every earlier image still
         * matches its own row first and nothing it selects changes. */
        {
            0xfc, 0x4b, 0xe9, 0xe3, 0xd6, 0x49, 0x46, 0xb7,
            0xef, 0x68, 0xf6, 0x1c, 0xe6, 0x07, 0x2f, 0x2f,
        },
        {
            0x14, 0x20, 0x84, 0x2d, 0x0f, 0xe7, 0x5c, 0xcb,
            0x12, 0xae, 0x8b, 0x9b, 0xac, 0xe4, 0x65, 0x2e,
            0x69, 0x5f, 0xcf, 0x73, 0xf8, 0xbd, 0x5b, 0x16,
            0x25, 0x6e, 0x16, 0x3a, 0x57, 0x03, 0xb6, 0x90,
        },
    },
    /* 23A341 (iOS 26.0), sep-firmware.d16.RELEASE.im4p: decrypted with this
     * row it opens with the same reset prologue as the builds above. */
    {
        {
            0x4a, 0xb2, 0xaf, 0xe3, 0x83, 0x07, 0x4b, 0xd7,
            0xf9, 0x81, 0xb5, 0x61, 0x00, 0x41, 0x03, 0xb9,
        },
        {
            0x20, 0xaa, 0xcf, 0x32, 0x52, 0xf7, 0x7f, 0xcd,
            0xd6, 0x92, 0x95, 0x12, 0xa5, 0x72, 0xe7, 0x68,
            0xa7, 0xfb, 0x57, 0xda, 0x58, 0x8c, 0xcb, 0x1e,
            0x58, 0xe2, 0x16, 0x1b, 0xd6, 0xc2, 0x69, 0xef,
        },
    },
    /*
     * 22G100 (iPhone14,4, iOS 18.6.2): sep-firmware.d16.RELEASE.im4p, two
     * wrapped keybags like 24A437's.  The iv/key are the public ones
     * (Keys:CrystalG_22G100_(iPhone14,4) on The Apple Wiki); verified
     * 2026-10-14 by decrypting the payload with them: the first block is
     * `01 00 00 10 e2 3f 00 10 02 c0 18 d5 fd 0f 00 14`.  Appended last, so
     * every build already in the table keeps its index and its event code.
     */
    {
        {
            0x6f, 0x15, 0x43, 0x4b, 0x28, 0xfe, 0xf5, 0x52,
            0xd4, 0x89, 0x64, 0x57, 0x28, 0x17, 0x3f, 0x6d,
        },
        {
            0x44, 0xd5, 0xd9, 0xe0, 0xf2, 0x47, 0xf8, 0xfc,
            0x96, 0x58, 0xc0, 0xba, 0xa8, 0x17, 0x6f, 0x14,
            0x13, 0x16, 0xce, 0x53, 0x32, 0x4b, 0x47, 0xc4,
            0xc0, 0xb2, 0xfd, 0x1f, 0x5d, 0x6a, 0x0d, 0x15,
        },
    },
};

sep_u32 sep_platform_firmware_key_count(void) {
    return (sep_u32)(sizeof(platform_firmware_keys) /
                     sizeof(platform_firmware_keys[0]));
}

sep_bool sep_platform_firmware_key_at(
    sep_u32 index,
    sep_shared_image_payload_keybag_t *keybag
) {
    if (keybag == 0 || index >= sep_platform_firmware_key_count()) {
        return 0;
    }
    const platform_firmware_key_t *entry = &platform_firmware_keys[index];
    sep_memmove(keybag->metadata, entry->iv, sizeof(entry->iv));
    sep_memmove(keybag->key, entry->key, sizeof(entry->key));
    keybag->key_bit_length = 8 * (sep_u32)sizeof(entry->key);
    keybag->present = 1;
    return 1;
}

sep_bool sep_platform_firmware_key(sep_shared_image_payload_keybag_t *keybag) {
    return sep_platform_firmware_key_at(0, keybag);
}

sep_bool sep_platform_runtime_configuration_hook_enabled(
    sep_u32 configuration_index
) {
    (void)configuration_index;
    return 0;
}

sep_bool sep_platform_runtime_feature0_enabled(void) {
    return 0;
}

sep_bool sep_platform_runtime_feature1_enabled(void) {
    return 0;
}

int sep_platform_wrak_autk_stage_status(void) {
    return 0;
}

void sep_platform_wrak_autk_prepare_hkdf_info(
    void *info,
    sep_size_t info_length
) {
    (void)info;
    (void)info_length;
}

sep_u32 sep_platform_wrak_autk_slot_count(void) {
    return 0;
}

int sep_platform_runtime_region_table_reset_status(void) {
    return 0;
}

void sep_platform_wrak_autk_post_install(void) {}

sep_u32 sep_platform_zero_result_stub(void) {
    return 0;
}

int sep_platform_main_initialize_status(void) {
    return 0;
}

void sep_platform_main_post_initialize(void) {}

void sep_platform_mode4_block0_optional_hook(void) {}

void sep_platform_mode4_block1_optional_hook(void) {}

void sep_runtime_mode_configuration_complete_hook(sep_u32 runtime_mode) {
    (void)runtime_mode;
}

void sep_main_platform_configuration_ready_hook(void) {}

void sep_main_platform_configuration_fallback_hook(void) {}
