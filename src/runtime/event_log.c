#include "open_secure_rom/event_log.h"

#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

static sep_u32 event_log[16];
static sep_u32 event_log_next;
static sep_u32 event_log_total;
static sep_u32 diagnostic_record[8];

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    if (event_log_next >= 16 || event_log_total == UINT32_MAX) {
        sep_fatal_wait_loop();
    }
    event_log[event_log_next] = event_code;
    event_log_next = event_log_next == 15 ? 0 : event_log_next + 1;
    ++event_log_total;
    return event_code;
}

void sep_protocol_diagnostic_record_write(
    sep_u32 event_code,
    const void *payload,
    sep_size_t payload_length
) {
    sep_protocol_event_log_append(event_code);
    sep_memzero(diagnostic_record, sizeof(diagnostic_record));
    diagnostic_record[0] = event_code;
    const sep_size_t payload_capacity =
        sizeof(diagnostic_record) - sizeof(event_code);
    const sep_size_t copied_length =
        payload_length < payload_capacity ? payload_length : payload_capacity;
    if (copied_length != 0) {
        sep_memmove_checked(
            (sep_u8 *)diagnostic_record + sizeof(event_code),
            payload,
            copied_length,
            payload_capacity
        );
    }
}

void sep_protocol_log_diagnostic_payload(
    sep_u32 event_code,
    const void *payload,
    sep_size_t payload_length
) {
    const sep_u32 policy = sep_platform_read_flag_08_encoded();
    if ((policy & 0xfe) != 0 || ((policy & 1) != 0 && policy >= 0x200)) {
        sep_fatal_wait_loop();
    }
    if (((policy & 1) != 0 && policy < 0x100) ||
        sep_platform_diagnostic_disclosure_enabled()) {
        sep_protocol_diagnostic_record_write(
            event_code,
            payload,
            payload_length
        );
        return;
    }
    sep_protocol_event_log_append(event_code & 0xefffffff);
}

void sep_protocol_event_log_snapshot(
    sep_u32 output[16],
    sep_size_t output_length
) {
    if (output_length != sizeof(event_log)) {
        sep_fatal_wait_loop();
    }
    sep_memzero(output, output_length);
    const sep_size_t count = event_log_total >= 16 ? 16 : event_log_total;
    const sep_size_t start = event_log_total >= 16 ? event_log_next : 0;
    for (sep_size_t index = 0; index < count; ++index) {
        output[index] = event_log[(start + index) & 15];
    }
}

void sep_protocol_diagnostic_record_snapshot(
    sep_u32 output[8],
    sep_size_t output_length
) {
    if (output_length != sizeof(diagnostic_record)) {
        sep_fatal_wait_loop();
    }
    sep_memmove(output, diagnostic_record, output_length);
}
