#include "open_secure_rom/runtime.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/panic.h"

extern void open_secure_rom_tlbi_vaale1(sep_u64 operand);
extern void open_secure_rom_tlbi_vmalle1(void);

void sep_platform_runtime_barrier_noop(void) {}

void sep_platform_counter_initialize(void) {}

void sep_platform_transition_stage_noop(sep_u32 stage) {
    (void)stage;
}

void sep_configure_timer_event_stream(void) {
    const sep_u64 cntkctl = 0x54;
    sep_platform_transition_stage_noop(1);
    __asm__ volatile("msr cntkctl_el1, %0\n\tisb" :: "r"(cntkctl) : "memory");
    sep_platform_transition_stage_noop(2);
}

void sep_disable_el0_system_controls(void) {
    sep_u64 sctlr;
    sep_u64 cntkctl;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    __asm__ volatile("mrs %0, cntkctl_el1" : "=r"(cntkctl));
    sctlr &= 0xfffffffffbfabdffULL;
    cntkctl &= 0xfffffffffffffdfeULL;
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(sctlr) : "memory");
    __asm__ volatile("msr cntkctl_el1, %0" :: "r"(cntkctl) : "memory");
}

void sep_dcache_clean_invalidate_range(const void *address, sep_size_t length) {
    sep_dcache_maintain_range(address, length, 1);
}

void sep_dcache_maintain_range(
    const void *address,
    sep_size_t length,
    sep_bool invalidate_after_clean
) {
    const uintptr_t start = (uintptr_t)address;
    if (length > UINTPTR_MAX - start) {
        sep_fatal_wait_loop();
    }
    const uintptr_t end = start + length;
    for (uintptr_t current = start; current < end; current += 64) {
        if (invalidate_after_clean) {
            sep_dcache_clean_invalidate_by_va((const void *)current);
        } else {
            sep_dcache_clean_by_va((const void *)current);
        }
        if (current > UINTPTR_MAX - 64) {
            sep_fatal_wait_loop();
        }
    }
    __asm__ volatile("dsb sy" ::: "memory");
}

void sep_tlb_invalidate_range_or_all(
    sep_u64 virtual_address,
    sep_size_t length
) {
    __asm__ volatile("dsb sy" ::: "memory");
    if (length <= 0x80000) {
        for (sep_size_t offset = 0; offset < length; offset += 0x4000) {
            open_secure_rom_tlbi_vaale1((virtual_address + offset) >> 12);
        }
    } else {
        open_secure_rom_tlbi_vmalle1();
    }
    __asm__ volatile("dsb sy\n\tisb" ::: "memory");
}

void sep_set_sctlr_el1_enib(sep_bool enabled) {
    sep_u64 sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr &= ~0x40000000ULL;
    sctlr |= enabled ? 0x40000000ULL : 0;
    __asm__ volatile("msr sctlr_el1, %0\n\tdsb sy\n\tisb" :: "r"(sctlr) : "memory");
}

void __attribute__((naked)) sep_write_apibkey_el1(
    sep_u64 high __attribute__((unused)),
    sep_u64 low __attribute__((unused))
) {
    __asm__ volatile(
        ".inst 0xd5182141\n\t"
        ".inst 0xd5182160\n\t"
        "dsb sy\n\t"
        "isb\n\t"
        "ret"
    );
}

void __attribute__((naked)) sep_write_prediction_restriction_keys_el1(
    sep_u64 a_low __attribute__((unused)),
    sep_u64 a_high __attribute__((unused)),
    sep_u64 b_low __attribute__((unused)),
    sep_u64 b_high __attribute__((unused))
) {
    __asm__ volatile(
        ".inst 0xd51cfa00\n\t"
        ".inst 0xd51cfa21\n\t"
        ".inst 0xd51cfa42\n\t"
        ".inst 0xd51cfa63\n\t"
        "dsb sy\n\t"
        "isb\n\t"
        "ret"
    );
}

void __attribute__((naked)) sep_prepare_panic_caller_pc_from_x19(void) {
    __asm__ volatile(
        ".inst 0xaa1303e1\n\t"
        ".inst 0xdac143e1\n\t"
        "ret"
    );
}

sep_u64 sep_cntpct_ticks_from_microseconds(sep_u64 microseconds) {
    if (microseconds >= 0x0aaaaaaaaaaaaaabULL) {
        sep_fatal_wait_loop();
    }
    return microseconds * 24;
}

sep_u64 sep_read_time_microseconds(void) {
    return sep_read_cntpct_synchronized() / 24;
}

void sep_wait_until_cntpct(sep_u64 deadline) {
    while (sep_read_cntpct_synchronized() < deadline) {
        __asm__ volatile("wfe" ::: "memory");
    }
}

void sep_delay_microseconds(sep_u32 microseconds) {
    if (microseconds == 0) {
        return;
    }
    const sep_u64 now = sep_read_time_microseconds();
    const sep_u64 deadline = now + microseconds;
    if (deadline < now) {
        sep_panic_reason_1c();
    }
    sep_protocol_event_log_append(0x000a0001);
    sep_wait_until_cntpct(sep_cntpct_ticks_from_microseconds(deadline));
    sep_protocol_event_log_append(0x000a0002);
}
