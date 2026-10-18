#include "open_secure_rom/event_log.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

int main(void) {
    for (sep_u32 event = 1; event <= 20; ++event) {
        assert(sep_protocol_event_log_append(event) == event);
    }

    sep_u32 events[16];
    sep_protocol_event_log_snapshot(events, sizeof(events));
    for (sep_u32 index = 0; index < 16; ++index) {
        assert(events[index] == index + 5);
    }

    const sep_u8 payload[32] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
    };
    sep_protocol_diagnostic_record_write(0x12345678, payload, sizeof(payload));
    sep_u32 record[8];
    sep_protocol_diagnostic_record_snapshot(record, sizeof(record));
    assert(record[0] == 0x12345678);
    assert(((const sep_u8 *)record)[4] == 0);
    assert(((const sep_u8 *)record)[31] == 27);
}
