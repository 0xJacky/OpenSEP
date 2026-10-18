#ifndef OPEN_SECURE_ROM_PANIC_H
#define OPEN_SECURE_ROM_PANIC_H

#include "open_secure_rom/types.h"

void __attribute__((noreturn)) sep_panic_with_reason_and_pc(
    sep_u32 reason,
    sep_u64 caller_pc
);
void sep_panic_unwind_frame_chain(
    sep_u64 *return_addresses,
    sep_size_t max_frames,
    sep_u64 frame_pointer
);
void sep_panic_mailbox_send_record(const void *record);
void sep_panic_mailbox_write_qword(sep_u64 value);
sep_bool sep_try_read_stack_qword(sep_u64 address, sep_u64 *value);
void sep_prepare_panic_caller_pc_from_x19(void);
sep_u64 sep_panic_record_magic(void);
sep_u8 sep_panic_get_auxiliary_state_byte(void);
void __attribute__((noreturn)) sep_assertion_fail_with_site(
    const void *site_tag
);
const void *sep_assertion_get_last_site_tag(void);
void __attribute__((noreturn)) sep_abort_to_fatal_wait_loop(void);
void __attribute__((noreturn)) sep_wait_for_event_forever(void);

#define SEP_DECLARE_PANIC_REASON(name) \
    void __attribute__((noreturn)) sep_panic_reason_##name(void)

SEP_DECLARE_PANIC_REASON(12e);
SEP_DECLARE_PANIC_REASON(1a);
SEP_DECLARE_PANIC_REASON(1c);
SEP_DECLARE_PANIC_REASON(1d);
SEP_DECLARE_PANIC_REASON(1e);
SEP_DECLARE_PANIC_REASON(22);
SEP_DECLARE_PANIC_REASON(23);
SEP_DECLARE_PANIC_REASON(27);
SEP_DECLARE_PANIC_REASON(2a);
SEP_DECLARE_PANIC_REASON(2b);
SEP_DECLARE_PANIC_REASON(2d);
SEP_DECLARE_PANIC_REASON(2f);

#undef SEP_DECLARE_PANIC_REASON

#endif
