#include "open_secure_rom/provisioning.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

enum {
    PROVISIONING_PROVIDER_OFFSET = 8,
    PROVISIONING_PROVIDER_SLOT_OFFSET = 16,
    PROVISIONING_RECORDS_OFFSET = 24,
    PROVISIONING_OPTIONAL_KEY_OFFSET = 121,
    PROVISIONING_OPTIONAL_SEED_OFFSET = 170,
    PROVISIONING_SCRATCH_OFFSET = 191,
    PROVISIONING_SCRATCH_CAPACITY = 192,
};

static sep_platform_provisioning_state_t provisioning_state
    OPEN_SECURE_ROM_SECTION(".platform_provisioning_state")
    __attribute__((used, aligned(8)));

static sep_u64 *state_records(sep_platform_provisioning_state_t *state) {
    return (sep_u64 *)&state->bytes[PROVISIONING_RECORDS_OFFSET];
}

sep_u64 *sep_platform_provisioning_cursor_store_checked(
    sep_u64 *destination,
    sep_u64 value
) {
    if (destination == 0 || ((uintptr_t)destination & 7) != 0) {
        sep_fatal_wait_loop();
    }
    *destination = value;
    return destination;
}

sep_bool sep_platform_provisioning_read_bytes_stub(
    void *provider,
    sep_u32 offset,
    sep_size_t length,
    void *output,
    sep_size_t output_capacity
) {
    if (provider == 0 || ((uintptr_t)provider & 7) != 0 ||
        length > UINT32_MAX - offset || length > output_capacity ||
        (output == 0 && length != 0)) {
        sep_fatal_wait_loop();
    }
    sep_memzero(output, length);
    return 1;
}

sep_u64 *sep_platform_provisioning_limit_store_checked(
    sep_u64 *destination,
    sep_u64 value
) {
    return sep_platform_provisioning_cursor_store_checked(destination, value);
}

sep_bool sep_platform_provisioning_provider_request_succeeds(
    const void *provider,
    sep_u64 request,
    sep_u64 argument
) {
    (void)request;
    (void)argument;
    if (provider == 0 || ((uintptr_t)provider & 7) != 0) {
        sep_fatal_wait_loop();
    }
    return 1;
}

void sep_platform_provisioning_prepare_singleton(void) {
    sep_platform_provisioning_state_prepare(
        sep_platform_provisioning_state_get()
    );
}

void sep_platform_provisioning_state_prepare(
    sep_platform_provisioning_state_t *state
) {
    if (state == 0 || ((uintptr_t)state & 7) != 0 || state->bytes[0] >= 2) {
        sep_fatal_wait_loop();
    }
    if (state->bytes[0] == 0) {
        sep_platform_provisioning_cursor_store_checked(
            (sep_u64 *)&state->bytes[8],
            (sep_u64)(uintptr_t)&state->bytes[2]
        );
        sep_platform_provisioning_limit_store_checked(
            (sep_u64 *)&state->bytes[16],
            (sep_u64)(uintptr_t)&state->bytes[2]
        );
        state->bytes[0] = 1;
    }
}

void sep_platform_provisioning_provider_clear(void) {
    *sep_platform_provisioning_provider_slot() = 0;
}

sep_u64 *sep_platform_provisioning_provider_slot(void) {
    return (sep_u64 *)&provisioning_state.bytes[
        PROVISIONING_PROVIDER_SLOT_OFFSET
    ];
}

void sep_platform_provisioning_initialize(void) {
    if (sep_platform_zero_result_stub() != 0 ||
        provisioning_state.bytes[1] >= 2) {
        sep_fatal_wait_loop();
    }
    if (provisioning_state.bytes[1] == 0) {
        sep_platform_provisioning_state_prepare(&provisioning_state);
        sep_u64 *records = state_records(&provisioning_state);
        for (sep_size_t index = 0; index < 8; ++index) {
            sep_platform_provisioning_record_clear(records, index);
        }
        sep_memzero(
            &provisioning_state.bytes[PROVISIONING_OPTIONAL_KEY_OFFSET],
            sizeof(sep_optional_configuration_key48_t)
        );
        sep_memzero(
            &provisioning_state.bytes[PROVISIONING_OPTIONAL_SEED_OFFSET],
            sizeof(sep_optional_research_seed_t)
        );
        provisioning_state.bytes[1] = 1;
    }
}

sep_optional_configuration_key48_t
sep_platform_provisioning_get_optional_key48(void) {
    if (provisioning_state.bytes[0] != 1) {
        sep_fatal_wait_loop();
    }
    sep_optional_configuration_key48_t result;
    sep_memmove(
        &result,
        &provisioning_state.bytes[PROVISIONING_OPTIONAL_KEY_OFFSET],
        sizeof(result)
    );
    return result;
}

sep_optional_research_seed_t
sep_platform_provisioning_get_optional_research_seed(void) {
    if (provisioning_state.bytes[0] != 1) {
        sep_fatal_wait_loop();
    }
    sep_optional_research_seed_t result;
    sep_memmove(
        &result,
        &provisioning_state.bytes[PROVISIONING_OPTIONAL_SEED_OFFSET],
        sizeof(result)
    );
    return result;
}

sep_u64 *sep_platform_provisioning_record_zero_checked(sep_u64 *record) {
    if (((uintptr_t)record & 3) != 0) {
        sep_fatal_wait_loop();
    }
    *record = 0;
    return record;
}

void sep_platform_provisioning_record_clear(
    sep_u64 *records,
    sep_size_t index
) {
    if (((uintptr_t)records & 3) != 0 || index >= 8) {
        sep_fatal_wait_loop();
    }
    sep_u64 record = 0;
    sep_platform_provisioning_record_store(records, index, &record);
}

sep_u32 sep_platform_provisioning_record_index_event_bits(
    sep_size_t record_index
) {
    if ((sep_u32)record_index >= 0xff) {
        sep_fatal_wait_loop();
    }
    return (sep_u32)(((record_index & 7) << 8) + 0x100);
}

void sep_platform_provisioning_record_store(
    sep_u64 *records,
    sep_size_t index,
    const sep_u64 *record
) {
    if (((uintptr_t)records & 3) != 0 ||
        index > (UINTPTR_MAX - (uintptr_t)records) / sizeof(*records)) {
        sep_fatal_wait_loop();
    }
    records[index] = *record;
}

sep_bool sep_platform_provisioning_process_records(
    sep_platform_provisioning_state_t *state,
    sep_u8 record_type,
    sep_u64 callback_or_vtable_offset,
    sep_bool indirect_dispatch
) {
    if (state == 0 || ((uintptr_t)state & 7) != 0 || indirect_dispatch) {
        sep_fatal_wait_loop();
    }
    typedef sep_bool (*record_callback_t)(
        sep_platform_provisioning_state_t *,
        sep_size_t
    );
    record_callback_t callback = (record_callback_t)(uintptr_t)
        callback_or_vtable_offset;
    sep_u64 *records = state_records(state);
    for (;;) {
        sep_bool found = 0;
        sep_size_t selected = 0;
        sep_u32 selected_sequence = UINT32_MAX;
        for (sep_size_t index = 0; index < 8; ++index) {
            const sep_u64 record = records[index];
            const sep_u8 type = (sep_u8)(record >> 32);
            const sep_u32 sequence = (sep_u32)record;
            if (type == record_type && (!found || sequence <= selected_sequence)) {
                found = 1;
                selected = index;
                selected_sequence = sequence;
            }
        }
        if (!found) {
            sep_protocol_event_log_append(
                ((sep_u32)record_type << 8) | 0x4009000b
            );
            return 0;
        }
        if (callback(state, selected)) {
            return 1;
        }
        sep_platform_provisioning_record_clear(records, selected);
    }
}

sep_u64 sep_platform_provisioning_record_word_at(
    const sep_u64 *records,
    sep_size_t index
) {
    if (((uintptr_t)records & 3) != 0 || index >= 8 ||
        index > (UINTPTR_MAX - (uintptr_t)records) / sizeof(*records)) {
        sep_fatal_wait_loop();
    }
    return records[index];
}

sep_bool sep_platform_provisioning_record_crc16_is_valid(
    sep_platform_provisioning_state_t *state,
    sep_size_t record_index
) {
    if (state == 0 || ((uintptr_t)state & 7) != 0) {
        sep_fatal_wait_loop();
    }
    const sep_u64 record = sep_platform_provisioning_record_word_at(
        state_records(state),
        record_index
    );
    const sep_size_t length = (record >> 40) & 0xff;
    if (length > PROVISIONING_SCRATCH_CAPACITY) {
        return 0;
    }
    sep_u8 *scratch = &state->bytes[PROVISIONING_SCRATCH_OFFSET];
    sep_platform_provisioning_read_bytes_stub(
        &state->bytes[PROVISIONING_PROVIDER_OFFSET],
        ((sep_u32)record_index << 8) | 0x40,
        length,
        scratch,
        PROVISIONING_SCRATCH_CAPACITY
    );
    return sep_crc16_update(scratch, length, 0xffff) ==
        (sep_u16)(record >> 48);
}

sep_platform_provisioning_state_t *sep_platform_provisioning_state_get(void) {
    return &provisioning_state;
}

void sep_platform_provisioning_state_reset(void) {
    sep_memzero(&provisioning_state, sizeof(provisioning_state));
}
