#include "open_secure_rom/provisioning.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    return event_code;
}

sep_u32 sep_platform_zero_result_stub(void) {
    return 0;
}

static sep_bool accept_record(
    sep_platform_provisioning_state_t *state,
    sep_size_t record_index
) {
    (void)state;
    return record_index == 1;
}

int main(void) {
    static const sep_u8 check[] = "123456789";
    assert(sep_crc16_update(check, 9, 0xffff) == 0x29b1);

    sep_platform_provisioning_state_reset();
    sep_platform_provisioning_state_t *state =
        sep_platform_provisioning_state_get();
    sep_platform_provisioning_state_prepare(state);
    assert(state->bytes[0] == 1);
    assert((sep_u8 *)sep_platform_provisioning_provider_slot() ==
        &state->bytes[16]);

    sep_u8 output[12];
    for (sep_size_t index = 0; index < sizeof(output); ++index) {
        output[index] = 0xa5;
    }
    assert(sep_platform_provisioning_read_bytes_stub(
        &state->bytes[8],
        4,
        sizeof(output),
        output,
        sizeof(output)
    ) == 1);
    for (sep_size_t index = 0; index < sizeof(output); ++index) {
        assert(output[index] == 0);
    }

    sep_u64 *records = (sep_u64 *)&state->bytes[24];
    sep_u64 record = 7 | ((sep_u64)2 << 32);
    sep_platform_provisioning_record_store(records, 1, &record);
    assert(sep_platform_provisioning_record_word_at(records, 1) == record);
    assert(sep_platform_provisioning_record_index_event_bits(7) == 0x800);
    assert(sep_platform_provisioning_process_records(
        state,
        2,
        (sep_u64)(uintptr_t)accept_record,
        0
    ) == 1);

    const sep_u8 zeroes[3] = {0, 0, 0};
    const sep_u16 crc = sep_crc16_update(zeroes, sizeof(zeroes), 0xffff);
    record = 1 | ((sep_u64)1 << 32) | ((sep_u64)3 << 40) |
        ((sep_u64)crc << 48);
    sep_platform_provisioning_record_store(records, 0, &record);
    assert(sep_platform_provisioning_record_crc16_is_valid(state, 0) == 1);

    sep_platform_provisioning_state_reset();
    sep_platform_provisioning_initialize();
    assert(sep_platform_provisioning_get_optional_key48().present == 0);
    assert(sep_platform_provisioning_get_optional_research_seed().present == 0);
}
