#include "open_secure_rom/wrak.h"

#include "open_secure_rom/ake.h"
#include "open_secure_rom/crypto_hmac.h"
#include "open_secure_rom/event_log.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/protocol.h"
#include "open_secure_rom/runtime.h"

enum {
    WRAK_STATE_SIZE = 0x60,
    WRAK_RESULT_SIZE = 0x3d,
};

static volatile sep_u8 *wrak_state(void) {
#ifdef OPEN_SECURE_ROM_HOST_TEST
    static sep_u8 state[WRAK_STATE_SIZE];
    return state;
#else
    return (volatile sep_u8 *)(uintptr_t)0x04020a70;
#endif
}

#ifdef OPEN_SECURE_ROM_HOST_TEST
sep_u8 *open_secure_rom_wrak_test_state(void) {
    return (sep_u8 *)wrak_state();
}
#endif

#define WRAK_PANIC(reason) \
    sep_panic_with_reason_and_pc( \
        reason, \
        (sep_u64)(uintptr_t)__builtin_return_address(0) \
    )

sep_bool sep_wrak_autk_buffer_has_nonzero_byte(
    const void *buffer,
    sep_size_t length
) {
    const sep_u8 *bytes = buffer;
    sep_u8 combined = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        if ((uintptr_t)bytes > UINTPTR_MAX - index) {
            sep_panic_reason_2f();
        }
        if (bytes == 0) {
            sep_panic_reason_1a();
        }
        combined |= bytes[index];
    }
    return combined != 0;
}

void sep_wrak_autk_apply_selector_to_provider(
    sep_u32 selector,
    sep_u8 provider_index
) {
    (void)provider_index;
    if (selector >= 6) {
        WRAK_PANIC(0x5f);
    }
}

void sep_wrak_autk_apply_selector_to_all_providers(sep_u32 selector) {
    for (sep_u8 index = 0;
         index < sep_platform_wrak_autk_slot_count();
         ++index) {
        sep_wrak_autk_apply_selector_to_provider(selector, index);
    }
}

void sep_wrak_autk_install_autp_provider_noop(
    const sep_u8 material[28],
    sep_u8 provider_index
) {
    (void)material;
    (void)provider_index;
}

void sep_wrak_autk_install_autp_material(
    const sep_u8 material[28],
    sep_u64 slot_group
) {
    if (!sep_wrak_autk_buffer_has_nonzero_byte(material, 28)) {
        WRAK_PANIC(0x36);
    }
    sep_platform_autp_install_begin_noop(material, 28, slot_group, "autp");
    for (sep_u8 index = 0;
         index < sep_platform_wrak_autk_slot_count();
         ++index) {
        sep_wrak_autk_install_autp_provider_noop(material, index);
    }
}

void sep_wrak_autk_install_labeled_key_material(
    const sep_u8 material[28],
    sep_u32 selector,
    const char *label
) {
    if (!sep_wrak_autk_buffer_has_nonzero_byte(material, 28)) {
        WRAK_PANIC(0x45);
    }
    sep_platform_wrak_autk_install_begin_noop(
        material,
        28,
        selector,
        label
    );
    if (selector > 1) {
        sep_wrak_autk_apply_selector_to_all_providers(2);
        sep_platform_wrak_autk_invalid_selector_noop(2);
        selector = 4;
    } else {
        sep_platform_wrak_autk_valid_selector_noop(selector);
    }
    sep_wrak_autk_apply_selector_to_all_providers(selector);
}

void sep_wrak_autk_commit_research_pattern(void) {
    sep_u8 material[28];
    sep_fill_research_seed_pattern(material, sizeof(material));
    sep_wrak_autk_install_autp_material(material, 1);
}

void sep_wrak_autk_stage_research_pattern(void) {
    volatile sep_u8 *state = wrak_state();
    if ((state[1] & 1) != 0 || state[2] == 1) {
        sep_protocol_event_log_append(0x800b0002);
        WRAK_PANIC(220);
    }
    if (sep_platform_wrak_autk_stage_status() != 0) {
        sep_protocol_event_log_append(0x800b0001);
        WRAK_PANIC(222);
    }
    sep_fill_research_seed_pattern((void *)&state[4], 28);
    sep_wrak_autk_install_autp_material((const sep_u8 *)&state[4], 1);
    state[3] = 1;
}

sep_u32 sep_wrak_autk_read_result_word(sep_size_t byte_offset) {
    volatile sep_u8 *state = wrak_state();
    if ((state[0] & 1) == 0) {
        WRAK_PANIC(211);
    }
    if (byte_offset >= WRAK_RESULT_SIZE) {
        WRAK_PANIC(212);
    }
    if ((uintptr_t)&state[0x20] > UINTPTR_MAX - byte_offset) {
        sep_panic_reason_2f();
    }
    const volatile sep_u8 *bytes = &state[0x20 + byte_offset];
    return (sep_u32)bytes[0] |
        ((sep_u32)bytes[1] << 8) |
        ((sep_u32)bytes[2] << 16) |
        ((sep_u32)bytes[3] << 24);
}

sep_bool sep_wrak_autk_load_authenticated_record_material(
    sep_u8 record_type,
    sep_u8 output[28]
) {
    sep_u8 record[32];
    sep_memzero(record, sizeof(record));
    sep_bool found = sep_ake_find_authenticated_record(record_type, record);
    if (found) {
        sep_memmove(output, record, 28);
        if (!sep_wrak_autk_buffer_has_nonzero_byte(output, 28)) {
            WRAK_PANIC(194);
        }
    }
    return found;
}

void sep_wrak_autk_import_type7_record(void) {
    volatile sep_u8 *state = wrak_state();
    if (state[3] == 1) {
        sep_protocol_event_log_append(0x800b0004);
        WRAK_PANIC(243);
    }
    if (state[2] == 1) {
        WRAK_PANIC(246);
    }
    if (sep_platform_wrak_autk_stage_status() != 0) {
        sep_protocol_event_log_append(0x800b0003);
        WRAK_PANIC(249);
    }
    if (!sep_wrak_autk_load_authenticated_record_material(
            7,
            (sep_u8 *)&state[4]
        )) {
        WRAK_PANIC(252);
    }
    sep_wrak_autk_install_autp_material((const sep_u8 *)&state[4], 1);
    state[1] = 1;
}

void sep_wrak_autk_derive_and_install_from_type8_record(void) {
    volatile sep_u8 *state = wrak_state();
    sep_u8 record[28];
    sep_u8 research_material[28];
    sep_u8 shib_key[32];
    sep_u8 derived[60];
    sep_u8 info[104];
    sep_u8 transformed[32];
    sep_u8 final_material[32];

    if (state[3] == 1) {
        WRAK_PANIC(269);
    }
    if ((state[1] & 1) == 0) {
        WRAK_PANIC(271);
    }
    if (sep_platform_wrak_autk_stage_status() != 0) {
        WRAK_PANIC(274);
    }
    if (!sep_wrak_autk_load_authenticated_record_material(8, record)) {
        WRAK_PANIC(277);
    }

    sep_platform_wrak_autk_post_install();
    sep_fill_research_seed_pattern(research_material, sizeof(research_material));
    sep_wrak_autk_install_labeled_key_material(
        research_material,
        0,
        "wrak"
    );
    sep_wrak_autk_install_labeled_key_material(
        research_material,
        2,
        "autk"
    );

    sep_u32 required_capabilities =
        sep_platform_required_capability_mask_zero_stub();
    sep_platform_key_service_finalize_noop(0);
    sep_memzero(shib_key, sizeof(shib_key));
    if (!sep_wrak_autk_buffer_has_nonzero_byte(record, 24)) {
        WRAK_PANIC(117);
    }
    sep_platform_key_material_transform_noop(
        "shib",
        record,
        24,
        shib_key,
        sizeof(shib_key)
    );
    sep_memzero(info, sizeof(info));
    sep_platform_wrak_autk_prepare_hkdf_info(info, sizeof(info));
    if (sep_hkdf_by_bit_length(
            384,
            sizeof(shib_key),
            shib_key,
            0,
            0,
            sizeof(info),
            info,
            sizeof(derived),
            derived
        ) != 0) {
        WRAK_PANIC(131);
    }

    sep_wrak_autk_install_autp_material(derived, 0);
    sep_platform_key_service_finalize_noop(required_capabilities);
    if (!sep_wrak_autk_buffer_has_nonzero_byte(&derived[28], 32)) {
        WRAK_PANIC(143);
    }

    sep_platform_wrak_autk_derivation_begin_noop(
        0,
        &derived[28],
        32,
        (void *)&state[64],
        32
    );
    if (!sep_wrak_autk_buffer_has_nonzero_byte((const void *)&state[64], 32)) {
        WRAK_PANIC(151);
    }
    sep_memzero(transformed, sizeof(transformed));
    sep_platform_wrak_autk_derivation_end_noop(
        0,
        (const void *)&state[64],
        32,
        transformed,
        sizeof(transformed)
    );
    state[32] = 0x40;
    state[33] = 0xb0;
    state[34] = 0;
    state[35] = 0;

    sep_memmove(transformed, &transformed[16], 16);
    sep_memzero(&transformed[16], 12);
    transformed[28] = 0x40;
    transformed[29] = 0xb0;
    transformed[30] = 0;
    transformed[31] = 0;
    if (!sep_wrak_autk_buffer_has_nonzero_byte(transformed, 32)) {
        WRAK_PANIC(169);
    }

    sep_memzero(final_material, sizeof(final_material));
    sep_platform_wrak_autk_derivation_end_noop(
        2,
        transformed,
        sizeof(transformed),
        final_material,
        sizeof(final_material)
    );
    if (!sep_wrak_autk_buffer_has_nonzero_byte(&final_material[16], 16)) {
        WRAK_PANIC(172);
    }
    sep_memmove((void *)&state[48], &final_material[16], 16);
    state[0] = 1;
    state[2] = 1;
}

#undef WRAK_PANIC
