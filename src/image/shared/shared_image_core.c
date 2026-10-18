#include "open_secure_rom/shared_image.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

static void require_context(const sep_shared_image_context_t *context) {
    if (context == 0 || ((uintptr_t)context & 7) != 0) {
        sep_fatal_wait_loop();
    }
}

void sep_shared_image_context_set_mode(
    sep_shared_image_context_t *context,
    sep_u8 mode
) {
    require_context(context);
    context->decoded_properties[0] = mode;
}

void sep_shared_image_context_set_payload_type(
    sep_shared_image_context_t *context,
    sep_u32 payload_type
) {
    require_context(context);
    sep_memmove(&context->decoded_properties[4], &payload_type, sizeof(payload_type));
}

sep_u8 sep_shared_image_context_mode_checked(
    const sep_shared_image_context_t *context
) {
    require_context(context);
    const sep_u8 mode = context->decoded_properties[0];
    if (mode == 2) {
        sep_fatal_wait_loop();
    }
    return mode;
}

sep_u32 sep_shared_image_context_payload_type_checked(
    const sep_shared_image_context_t *context
) {
    require_context(context);
    sep_u32 payload_type;
    sep_memmove(&payload_type, &context->decoded_properties[4], sizeof(payload_type));
    if (payload_type == 0) {
        sep_fatal_wait_loop();
    }
    return payload_type;
}

sep_optional_configuration_key48_t
sep_shared_image_context_get_optional_key48(
    const sep_shared_image_context_t *context
) {
    require_context(context);
    sep_optional_configuration_key48_t result;
    sep_memmove(result.bytes, &context->decoded_properties[57], sizeof(result.bytes));
    result.present = context->decoded_properties[105];
    return result;
}

void sep_shared_image_auxiliary_initialize(
    sep_shared_image_auxiliary_t *auxiliary
) {
    sep_shared_image_auxiliary_initialize_fields(auxiliary);
}

void sep_shared_image_auxiliary_initialize_fields(
    sep_shared_image_auxiliary_t *auxiliary
) {
    if (auxiliary == 0 || ((uintptr_t)auxiliary & 3) != 0) {
        sep_fatal_wait_loop();
    }
    sep_memzero(auxiliary, sizeof(*auxiliary));
}

sep_shared_image_auxiliary_keybag_entry_t *
sep_shared_image_auxiliary_keybag_entry_at(
    sep_shared_image_auxiliary_t *auxiliary,
    sep_u32 index
) {
    if (auxiliary == 0 || ((uintptr_t)auxiliary & 3) != 0 || index >= 3) {
        sep_fatal_wait_loop();
    }
    return &auxiliary->entries[index];
}

void sep_shared_image_payload_keybag_initialize_absent(
    sep_shared_image_payload_keybag_t *keybag
) {
    sep_shared_image_payload_keybag_initialize_fields(keybag);
}

void sep_shared_image_payload_keybag_initialize_fields(
    sep_shared_image_payload_keybag_t *keybag
) {
    if (keybag == 0 || ((uintptr_t)keybag & 3) != 0) {
        sep_fatal_wait_loop();
    }
    sep_memzero(keybag, sizeof(*keybag));
}

sep_bool sep_shared_image_payload_keybag_is_present_and_allowed(
    const sep_shared_image_context_t *context,
    sep_bool allow_unrestricted
) {
    require_context(context);
    const sep_bool present = context->auxiliary[0];
    if (present >= 2 || allow_unrestricted >= 2) {
        sep_fatal_wait_loop();
    }
    if (present && !allow_unrestricted &&
        !sep_shared_image_properties_ekey_checked(
            (const sep_shared_image_properties_t *)context
        ) &&
        !sep_shared_image_properties_eg0t_checked(
            (const sep_shared_image_properties_t *)context
        )) {
        sep_protocol_event_log_append(0x8005001c);
        sep_fatal_wait_loop();
    }
    return present;
}

sep_bool sep_shared_image_strict_policy_is_enabled(void) {
    const sep_u16 flag = (sep_u16)sep_platform_read_flag_0c_encoded();
    const sep_u8 present = (sep_u8)flag;
    const sep_u8 value = (sep_u8)(flag >> 8);
    if (present >= 2 || value >= 2) {
        sep_fatal_wait_loop();
    }
    if (present == 0 || value == 1) {
        return 1;
    }
    return (sep_bool)(!sep_platform_zero_result_stub() &&
        !sep_platform_feature_gate());
}
