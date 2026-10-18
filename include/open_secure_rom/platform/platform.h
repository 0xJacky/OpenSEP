#ifndef OPEN_SECURE_ROM_PLATFORM_H
#define OPEN_SECURE_ROM_PLATFORM_H

#include "open_secure_rom/types.h"

sep_u32 sep_platform_capability_mask_zero_stub(sep_u32 capability_id);
sep_u32 sep_platform_required_capability_mask_zero_stub(void);
void sep_platform_key_service_finalize_noop(sep_u32 capability_mask);
void sep_platform_runtime_feature_commit_noop(
    sep_u32 feature_id,
    sep_bool enabled
);
sep_bool sep_platform_required_feature_supported_stub(sep_u32 feature_id);
void sep_platform_transition_noop_hook(sep_u32 feature_id, sep_bool enabled);
sep_bool sep_platform_optional_feature_supported_zero_stub(sep_u32 feature_id);
sep_bool sep_platform_payload_keybag_selector_zero_stub(
    void *output,
    const void *input,
    sep_size_t input_length,
    const sep_u8 iv[16],
    sep_size_t key_bit_length
);
void sep_platform_key_material_transform_noop(
    const char *label,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
);
void sep_platform_runtime_feature_preapply_noop(void);
void sep_platform_runtime_feature_postapply_noop(sep_u32 feature_id);
sep_bool sep_platform_payload_keybag_policy_zero_stub(sep_u32 policy_id);
void sep_platform_panic_record_prepare_noop(
    const void *constant,
    sep_size_t bit_length
);
void sep_platform_wrak_autk_install_begin_noop(
    const sep_u8 material[28],
    sep_size_t material_length,
    sep_u32 selector,
    const char *label
);
void sep_platform_wrak_autk_invalid_selector_noop(sep_u32 selector);
void sep_platform_wrak_autk_valid_selector_noop(sep_u32 selector);
void sep_platform_wrak_autk_derivation_begin_noop(
    sep_u32 selector,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
);
void sep_platform_wrak_autk_derivation_end_noop(
    sep_u32 selector,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
);
void sep_platform_autp_install_begin_noop(
    const sep_u8 material[28],
    sep_size_t material_length,
    sep_u32 selector,
    const char *label
);
void sep_platform_mode1_configuration_noop(
    const void *configuration,
    sep_size_t configuration_length,
    sep_u32 slot
);
void sep_platform_mode4_configuration_noop(
    const void *configuration,
    sep_size_t configuration_length,
    sep_u32 slot
);
void sep_platform_configuration_alternate_init_noop(void);
void sep_platform_configuration_initialize(void);
void sep_platform_configuration_seed_research_block(void);
void sep_platform_configuration_write_optional_key48(
    const sep_optional_configuration_key48_t *key,
    sep_u32 configuration_word,
    sep_bool include_key
);
void *sep_platform_configuration_write(
    sep_size_t offset,
    const void *source,
    sep_size_t length
);
void *sep_platform_configuration_read(
    sep_size_t offset,
    void *destination,
    sep_size_t length
);
void *sep_platform_configuration_write_mode1_block0(
    const void *block,
    sep_size_t length
);
void *sep_platform_configuration_write_mode1_block1(
    const void *block,
    sep_size_t length
);
void *sep_platform_configuration_read_mode1_block0(
    void *block,
    sep_size_t length
);
void *sep_platform_configuration_read_mode1_block1(
    void *block,
    sep_size_t length
);
void *sep_platform_configuration_write_mode4_block0(
    const void *block,
    sep_size_t length
);
void *sep_platform_configuration_write_mode4_block1(
    const void *block,
    sep_size_t length
);
void *sep_platform_configuration_read_mode4_block0(
    void *block,
    sep_size_t length
);
void *sep_platform_configuration_read_mode4_block1(
    void *block,
    sep_size_t length
);
sep_u32 sep_platform_configuration_read_runtime_feature_flags(void);
void *sep_platform_configuration_write_runtime_feature_flags(
    sep_u32 packed_flags
);
sep_u32 sep_platform_read_runtime_region_size_kib(void);
void sep_platform_runtime_authentication_finalize_noop(void);
void sep_platform_runtime_authentication_state_initialize(void);
void __attribute__((noreturn))
sep_platform_runtime_authentication_verify_or_panic(void);
void sep_platform_runtime_region_prepare_noop(sep_u32 runtime_mode);
void sep_platform_identity_initialize(void);
sep_u32 sep_platform_read_flag_0c_encoded(void);
sep_u32 sep_platform_read_flag_08_encoded(void);
sep_u32 sep_platform_read_flag_08_boolean_encoded(void);
sep_u32 sep_platform_read_flag_0c_boolean_encoded(void);
sep_u32 sep_platform_get_security_epoch(void);
sep_u32 sep_platform_get_chip_id(void);
sep_u64 sep_platform_read_ecid(void);
sep_u64 sep_platform_get_panic_context_word(void);
sep_u32 sep_platform_read_chip_revision(void);
sep_u32 sep_platform_read_security_domain_encoded(void);
sep_bool sep_platform_diagnostic_disclosure_enabled(void);
sep_bool sep_platform_primary_runtime_path_enabled(void);
sep_bool sep_platform_secondary_runtime_path_enabled(void);
int sep_platform_runtime_iteration_status(sep_u8 slot_index);
sep_bool sep_platform_feature_gate(void);
sep_bool sep_platform_firmware_key(sep_shared_image_payload_keybag_t *keybag);
sep_u32 sep_platform_firmware_key_count(void);
sep_bool sep_platform_firmware_key_at(
    sep_u32 index,
    sep_shared_image_payload_keybag_t *keybag
);
sep_bool sep_platform_runtime_configuration_hook_enabled(
    sep_u32 configuration_index
);
sep_bool sep_platform_runtime_feature0_enabled(void);
sep_bool sep_platform_runtime_feature1_enabled(void);
int sep_platform_wrak_autk_stage_status(void);
void sep_platform_wrak_autk_prepare_hkdf_info(
    void *info,
    sep_size_t info_length
);
sep_u32 sep_platform_wrak_autk_slot_count(void);
int sep_platform_runtime_region_table_reset_status(void);
void sep_platform_wrak_autk_post_install(void);
sep_u32 sep_platform_zero_result_stub(void);
void sep_platform_cache_provisioning_values(void);
sep_optional_configuration_key48_t
sep_platform_get_cached_optional_key48(void);
sep_optional_research_seed_t
sep_platform_get_cached_optional_research_seed(void);
int sep_platform_main_initialize_status(void);
void sep_platform_main_post_initialize(void);
void sep_platform_mode4_block0_optional_hook(void);
void sep_platform_mode4_block1_optional_hook(void);
void sep_runtime_mode_configuration_complete_hook(sep_u32 runtime_mode);
void sep_main_platform_configuration_ready_hook(void);
void sep_main_platform_configuration_fallback_hook(void);
void sep_platform_publish_runtime_region_size_kib(void);
void sep_runtime_feature_flags_validate_platform_support(
    const sep_runtime_feature_flags_t *flags
);
sep_runtime_feature_flags_t sep_runtime_feature_flags_decode(
    sep_u32 packed_flags
);
sep_u8 sep_runtime_feature_flags_pack(
    const sep_runtime_feature_flags_t *flags
);
void sep_runtime_feature_flags_apply(
    const sep_runtime_feature_flags_t *flags
);
void sep_platform_seed_runtime_mode_configuration_blocks(
    sep_u32 runtime_mode
);
void sep_platform_validate_runtime_mode_configuration_blocks(
    sep_u32 runtime_mode
);

#endif
