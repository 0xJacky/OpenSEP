#include "open_secure_rom/platform.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/runtime.h"

static void require_valid_feature_flags(
    const sep_runtime_feature_flags_t *flags
) {
    if (flags == 0 || flags->valid != 1) {
        sep_fatal_wait_loop();
    }
    for (sep_size_t index = 0; index < 8; ++index) {
        if (flags->flags[index] >= 2) {
            sep_fatal_wait_loop();
        }
    }
}

void sep_runtime_feature_flags_validate_platform_support(
    const sep_runtime_feature_flags_t *flags
) {
    require_valid_feature_flags(flags);

    const sep_u32 required = sep_platform_required_capability_mask_zero_stub();
    const sep_u32 available =
        sep_platform_capability_mask_zero_stub(0) |
        sep_platform_capability_mask_zero_stub(1);
    if (required != 0 || available != 0 ||
        (sep_platform_runtime_feature0_enabled() &&
            !sep_platform_optional_feature_supported_zero_stub(0)) ||
        (sep_platform_runtime_feature1_enabled() &&
            !sep_platform_optional_feature_supported_zero_stub(1)) ||
        !sep_platform_required_feature_supported_stub(0x1f) ||
        (sep_platform_diagnostic_disclosure_enabled() &&
            !sep_platform_required_feature_supported_stub(0x1e)) ||
        (flags->flags[1] &&
            !sep_platform_required_feature_supported_stub(0x1d)) ||
        (flags->flags[0] &&
            !sep_platform_required_feature_supported_stub(0x1c))) {
        sep_fatal_wait_loop();
    }
}

sep_runtime_feature_flags_t sep_runtime_feature_flags_decode(
    sep_u32 packed_flags
) {
    sep_runtime_feature_flags_t result = {.valid = 1};
    for (sep_u32 index = 0; index < 8; ++index) {
        result.flags[index] = (sep_bool)((packed_flags >> index) & 1);
    }
    return result;
}

sep_u8 sep_runtime_feature_flags_pack(
    const sep_runtime_feature_flags_t *flags
) {
    if (flags == 0) {
        sep_fatal_wait_loop();
    }
    sep_u8 packed = 0;
    for (sep_u32 index = 0; index < 8; ++index) {
        if (flags->flags[index] >= 2) {
            sep_fatal_wait_loop();
        }
        packed |= (sep_u8)(flags->flags[index] << index);
    }
    return packed;
}

void sep_runtime_feature_flags_apply(
    const sep_runtime_feature_flags_t *flags
) {
    require_valid_feature_flags(flags);

    if (flags->flags[1]) {
        sep_protocol_event_log_append(0x50004);
        sep_platform_transition_noop_hook(0x1d, 1);
    }
    if (flags->flags[0]) {
        sep_platform_transition_noop_hook(0x1c, 1);
        if (flags->flags[4]) {
            sep_protocol_event_log_append(0x5001d);
            sep_platform_runtime_feature_preapply_noop();
        }
        sep_protocol_event_log_append(0x50016);
        sep_platform_runtime_feature_postapply_noop(0);
        sep_protocol_event_log_append(0x50017);
        sep_platform_runtime_feature_postapply_noop(1);
        sep_protocol_event_log_append(0x50018);
        sep_platform_runtime_feature_postapply_noop(3);
        return;
    }

    sep_platform_runtime_feature_preapply_noop();
    if (!flags->flags[5]) {
        sep_protocol_event_log_append(0x50019);
        sep_platform_runtime_feature_postapply_noop(0);
    }
    if (!flags->flags[6]) {
        sep_protocol_event_log_append(0x5001a);
        sep_platform_runtime_feature_postapply_noop(1);
    }
    if (!flags->flags[7]) {
        sep_protocol_event_log_append(0x5001b);
        sep_platform_runtime_feature_postapply_noop(3);
    }
}
