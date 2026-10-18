#include "open_secure_rom/panic.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

enum {
    SEP_PANIC_RECORD_SIZE = 0x1a0,
    SEP_PANIC_RECORD_QWORDS = SEP_PANIC_RECORD_SIZE / 8,
};

static sep_u8 panic_recursion_state
    OPEN_SECURE_ROM_SECTION(".panic_recursion_state");
static const void *last_assertion_site
    OPEN_SECURE_ROM_SECTION(".assertion_state");
static sep_u8 panic_record[SEP_PANIC_RECORD_SIZE] __attribute__((aligned(8)));

sep_u64 sep_panic_record_magic(void) {
    return 0xddeeaaddbbeeeeffULL;
}

sep_u8 sep_panic_get_auxiliary_state_byte(void) {
#ifdef OPEN_SECURE_ROM_HOST_TEST
    return 0;
#else
    return *(const volatile sep_u8 *)(uintptr_t)0x04020e18;
#endif
}

const void *sep_assertion_get_last_site_tag(void) {
    return last_assertion_site;
}

void sep_panic_mailbox_write_qword(sep_u64 value) {
#ifdef OPEN_SECURE_ROM_HOST_TEST
    (void)value;
#else
    volatile sep_u32 *const status =
        (volatile sep_u32 *)(uintptr_t)0x05000020;
    volatile sep_u64 *const tx_low =
        (volatile sep_u64 *)(uintptr_t)0x05000200;
    volatile sep_u64 *const tx_high =
        (volatile sep_u64 *)(uintptr_t)0x05000208;
    while ((*status & (1U << 16)) != 0) {
        sep_wait_for_event_once_synchronized();
    }
    *tx_low = value;
    *tx_high = 0;
#endif
}

void sep_panic_mailbox_send_record(const void *record) {
    const sep_u64 *qwords = record;
    sep_panic_mailbox_write_qword(0x00ff00ff);
    sep_panic_mailbox_write_qword(sep_panic_record_magic());
    for (sep_size_t index = 0; index < SEP_PANIC_RECORD_QWORDS; ++index) {
        sep_panic_mailbox_write_qword(qwords[index]);
    }
}

sep_bool sep_try_read_stack_qword(sep_u64 address, sep_u64 *value) {
    if ((address & 7) != 0 ||
        address < 0x04028000 ||
        address > 0x0402fff8) {
        return 0;
    }
#ifdef OPEN_SECURE_ROM_HOST_TEST
    (void)value;
    return 0;
#else
    sep_u64 translation_result;
    __asm__ volatile(
        "at s1e1r, %1\n\t"
        "mrs %0, par_el1"
        : "=r"(translation_result)
        : "r"(address)
        : "memory"
    );
    const sep_u8 attributes = (sep_u8)(translation_result >> 56);
    if ((translation_result & 1) != 0 ||
        attributes == 0 || attributes == 4) {
        return 0;
    }
    *value = *(const volatile sep_u64 *)(uintptr_t)address;
    return 1;
#endif
}

void sep_panic_unwind_frame_chain(
    sep_u64 *return_addresses,
    sep_size_t max_frames,
    sep_u64 frame_pointer
) {
    const sep_size_t output_alignment =
        (sep_size_t)(uintptr_t)return_addresses & 7;
    while (max_frames != 0) {
        sep_u64 previous;
        sep_u64 return_address;
        if (!sep_try_read_stack_qword(frame_pointer, &previous)) {
            break;
        }
        if (frame_pointer >= UINT64_MAX - 7) {
            sep_panic_reason_1c();
        }
        if (!sep_try_read_stack_qword(frame_pointer + 8, &return_address)) {
            break;
        }
        if ((uintptr_t)return_addresses >= UINTPTR_MAX - 7) {
            sep_panic_reason_2f();
        }
        if (output_alignment != 0) {
            sep_panic_reason_1a();
        }
        *return_addresses++ = return_address;
        frame_pointer = previous;
        --max_frames;
    }
}

void __attribute__((noreturn)) sep_panic_with_reason_and_pc(
    sep_u32 reason,
    sep_u64 caller_pc
) {
    if (panic_recursion_state != 0) {
        sep_fatal_wait_loop();
    }
    panic_recursion_state = 1;
    sep_memzero(panic_record, sizeof(panic_record));
    *(sep_u64 *)&panic_record[0] = 255;
    *(sep_u64 *)&panic_record[8] = reason;
    *(sep_u64 *)&panic_record[16] =
        (sep_u64)(uintptr_t)__builtin_return_address(0);
    *(sep_u64 *)&panic_record[24] = caller_pc;
    *(sep_u64 *)&panic_record[32] = sep_platform_get_panic_context_word();
    sep_protocol_event_log_snapshot(
        (sep_u32 *)&panic_record[40],
        64
    );
    sep_protocol_diagnostic_record_snapshot(
        (sep_u32 *)&panic_record[104],
        32
    );
    *(sep_u64 *)&panic_record[208] =
        (sep_u64)(uintptr_t)last_assertion_site;
    panic_record[216] = sep_panic_get_auxiliary_state_byte();
    sep_panic_unwind_frame_chain(
        (sep_u64 *)&panic_record[224],
        24,
        (sep_u64)(uintptr_t)__builtin_frame_address(0)
    );
    sep_panic_mailbox_send_record(panic_record);
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_assertion_fail_with_site(
    const void *site_tag
) {
    last_assertion_site = site_tag;
    sep_panic_with_reason_and_pc(
        0x37,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_abort_to_fatal_wait_loop(void) {
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_wait_for_event_forever(void) {
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_panic_reason_12e(void) {
    sep_panic_with_reason_and_pc(
        0x12e,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_1a(void) {
    sep_panic_with_reason_and_pc(
        0x1a,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_1c(void) {
    sep_panic_with_reason_and_pc(
        0x1c,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_1d(void) {
    sep_panic_with_reason_and_pc(
        0x1d,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_1e(void) {
    sep_panic_with_reason_and_pc(
        0x1e,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_22(void) {
    sep_panic_with_reason_and_pc(
        0x22,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_23(void) {
    sep_panic_with_reason_and_pc(
        0x23,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_27(void) {
    sep_panic_with_reason_and_pc(
        0x27,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_2a(void) {
    sep_panic_with_reason_and_pc(
        0x2a,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_2b(void) {
    sep_panic_with_reason_and_pc(
        0x2b,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_2d(void) {
    sep_panic_with_reason_and_pc(
        0x2d,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_panic_reason_2f(void) {
    sep_panic_with_reason_and_pc(
        0x2f,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}
