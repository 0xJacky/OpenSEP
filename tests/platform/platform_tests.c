#include "open_secure_rom/platform.h"

#include <assert.h>

int main(void) {
    sep_u8 output[16] = {0};
    const sep_u8 input[16] = {0};
    const sep_u8 iv[16] = {0};

    assert(sep_platform_capability_mask_zero_stub(7) == 0);
    assert(sep_platform_required_capability_mask_zero_stub() == 0);
    assert(sep_platform_required_feature_supported_stub(3) == 1);
    assert(sep_platform_optional_feature_supported_zero_stub(3) == 0);
    assert(sep_platform_payload_keybag_selector_zero_stub(
        output,
        input,
        sizeof(input),
        iv,
        128
    ) == 0);
    assert(sep_platform_payload_keybag_policy_zero_stub(9) == 0);
    assert(sep_platform_zero_result_stub() == 0);
    assert(sep_platform_main_initialize_status() == 0);
    assert(sep_platform_get_security_epoch() == 0);
    assert(sep_platform_get_chip_id() == 0xfe01);
    assert(sep_platform_diagnostic_disclosure_enabled() == 0);
    assert(sep_platform_feature_gate() == 0);
    assert(sep_platform_runtime_feature0_enabled() == 0);
    assert(sep_platform_runtime_feature1_enabled() == 0);
    assert(sep_platform_get_panic_context_word() == 0);
    assert(sep_platform_primary_runtime_path_enabled() == 1);
    assert(sep_platform_secondary_runtime_path_enabled() == 1);
    assert(sep_platform_runtime_iteration_status(3) == 0);
    assert(sep_platform_runtime_configuration_hook_enabled(1) == 0);
    assert(sep_platform_wrak_autk_stage_status() == 0);
    assert(sep_platform_wrak_autk_slot_count() == 0);
    assert(sep_platform_runtime_region_table_reset_status() == 0);

    sep_platform_key_service_finalize_noop(0);
    sep_platform_runtime_feature_commit_noop(0, 1);
    sep_platform_transition_noop_hook(0, 1);
    sep_platform_key_material_transform_noop("label", input, 16, output, 16);
    sep_platform_panic_record_prepare_noop(input, 128);
    sep_platform_wrak_autk_install_begin_noop(input, 16, 0, "wrak");
    sep_platform_wrak_autk_invalid_selector_noop(2);
    sep_platform_wrak_autk_valid_selector_noop(1);
    sep_platform_wrak_autk_derivation_begin_noop(0, input, 16, output, 16);
    sep_platform_wrak_autk_derivation_end_noop(0, input, 16, output, 16);
    sep_platform_autp_install_begin_noop(input, 16, 0, "autp");
    sep_platform_runtime_feature_preapply_noop();
    sep_platform_runtime_feature_postapply_noop(0);
    sep_platform_mode1_configuration_noop(input, sizeof(input), 0);
    sep_platform_mode4_configuration_noop(input, sizeof(input), 2);
    sep_platform_configuration_alternate_init_noop();
    sep_platform_runtime_authentication_finalize_noop();
    sep_platform_runtime_region_prepare_noop(1);
    sep_platform_identity_initialize();
    sep_platform_wrak_autk_prepare_hkdf_info(output, sizeof(output));
    sep_platform_wrak_autk_post_install();
    sep_platform_main_post_initialize();
    sep_platform_mode4_block0_optional_hook();
    sep_platform_mode4_block1_optional_hook();
    sep_runtime_mode_configuration_complete_hook(1);
    sep_main_platform_configuration_ready_hook();
    sep_main_platform_configuration_fallback_hook();
}
