#include "open_secure_rom/system_closure.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

void sep_exception_build_panic_record(
    sep_u32 vector_kind,
    const sep_exception_frame_t *frame
) {
    if (frame == NULL || ((uintptr_t)frame & 7) != 0) {
        sep_panic_reason_1a();
    }
    open_secure_rom_exception_panic_record_t record;
    sep_u8 event_log[64];
    sep_protocol_event_log_snapshot((sep_u32 *)(void *)event_log, 64);
    open_secure_rom_exception_panic_record_initialize(
        &record,
        vector_kind,
        frame,
        sep_platform_get_panic_context_word(),
        event_log
    );
    sep_panic_unwind_frame_chain(
        record.return_addresses,
        31,
        frame->frame_pointer
    );
    sep_panic_mailbox_send_record(&record);
}

void __attribute__((noreturn)) sep_exception_handle_sync(
    sep_exception_frame_t *frame
) {
    sep_exception_build_panic_record(1, frame);
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_exception_handle_serror(
    sep_exception_frame_t *frame
) {
    sep_exception_build_panic_record(4, frame);
    sep_fatal_wait_loop();
}
