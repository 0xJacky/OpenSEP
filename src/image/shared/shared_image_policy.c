#include "open_secure_rom/shared_image.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/protocol.h"
#include "open_secure_rom/runtime.h"
#include "open_secure_rom/runtime_storage.h"

static sep_u16 policy_load_u16(const sep_u8 *bytes) {
    sep_u16 value;
    sep_memmove(&value, bytes, sizeof(value));
    return value;
}

sep_shared_image_research_policy_t
sep_shared_image_evaluate_research_policy(
    const sep_shared_image_context_t *context
) {
    if (context == 0 || ((uintptr_t)context & 7) != 0) {
        sep_fatal_wait_loop();
    }
    const sep_u8 *properties = context->decoded_properties;
    if (properties[56] >= 2) {
        sep_fatal_wait_loop();
    }
    sep_shared_image_research_policy_t status;
    if (properties[56]) {
        status = 1;
    } else {
        sep_protocol_event_log_append(0x40030004);
        status = 3;
    }

    if (!sep_optional_bool_matches_or_log(
            policy_load_u16(&properties[228]),
            (sep_u16)sep_platform_read_flag_08_boolean_encoded(),
            0x40030016,
            0x40030010
        )) {
        status = 4;
    }
    if (properties[242] >= 2) {
        sep_fatal_wait_loop();
    }
    if (!sep_optional_bool_matches_or_log(
            policy_load_u16(&properties[230]),
            (sep_u16)sep_platform_read_flag_0c_boolean_encoded(),
            0x40030015,
            0x4003000f
        )) {
        status = 5;
    }

    const sep_u8 mode = sep_shared_image_context_mode_checked(context);
    if (mode == 0) {
        if (properties[241] >= 2) {
            sep_fatal_wait_loop();
        }
        if (properties[241] == 0) {
            (void)sep_platform_get_cached_optional_key48();
        }
        return status;
    }
    if (mode != 1) {
        sep_fatal_wait_loop();
    }

    if (properties[206] >= 2) {
        sep_fatal_wait_loop();
    }
    if (properties[206] == 0) {
        return status;
    }
    const sep_checked_bytes20_t *expected =
        (const sep_checked_bytes20_t *)&properties[207];
    const sep_optional_research_seed_t current =
        sep_get_optional_research_seed();
    if (sep_optional_research_seed_is_present(&current) &&
        sep_checked_bytes20_equal(
            (const sep_checked_bytes20_t *)&current,
            expected
        )) {
        return status;
    }

    const sep_optional_research_seed_t cached =
        sep_platform_get_cached_optional_research_seed();
    if (sep_optional_research_seed_is_present(&cached) &&
        sep_checked_bytes20_equal(
            (const sep_checked_bytes20_t *)&cached,
            expected
        )) {
        return status;
    }
    if (sep_optional_research_seed_is_present(&cached)) {
        sep_protocol_log_diagnostic_payload(
            0x5005000e,
            sep_optional_research_seed_require_present(&cached),
            20
        );
    } else if (sep_optional_research_seed_is_present(&current)) {
        sep_protocol_log_diagnostic_payload(
            0x5005000f,
            sep_optional_research_seed_require_present(&current),
            20
        );
    } else {
        sep_protocol_event_log_append(0x40050012);
    }
    return 6;
}

void __attribute__((noreturn)) sep_shared_image_research_policy_panic(
    sep_shared_image_research_policy_t status
) {
    (void)status;
    sep_fatal_wait_loop();
}
