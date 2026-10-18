.text
.p2align 2

.global sep_boot_scrub_architectural_state_and_enter_runtime
.type sep_boot_scrub_architectural_state_and_enter_runtime,@function
sep_boot_scrub_architectural_state_and_enter_runtime:
    /*
     * x0 and x1 are the runtime's two arguments; x2 is where to enter it; x3,
     * when non-zero, goes to s3_7_c15_c2_0 on the way out.
     *
     * x1 is kept apart from the registers the scrub zeroes because the t8110
     * runtime's cold path copies sixteen kilobytes from it before it builds
     * anything.
     */
    mov x28, x0
    mov x29, x2
    mov x27, x1
    mov x26, x3
    bl sep_disable_el0_system_controls
    msr daifset, #0xf
    dsb sy
    isb
    msr sctlr_el1, xzr
    dsb sy
    isb
    tlbi vmalle1
    dsb sy
    isb
    msr elr_el1, xzr
    msr par_el1, xzr
    msr tpidr_el0, xzr
    msr tpidrro_el0, xzr
    msr tpidr_el1, xzr
    msr ttbr0_el1, xzr
    msr vbar_el1, xzr
    msr spsr_el1, xzr
    mov x2, xzr
    msr spsel, #0
    mov sp, x2
    msr spsel, #1
    mov sp, x2
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    mov x18, xzr
    mov x19, xzr
    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    mov x23, xzr
    mov x24, xzr
    mov x25, xzr
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    movi v4.16b, #0
    movi v5.16b, #0
    movi v6.16b, #0
    movi v7.16b, #0
    movi v8.16b, #0
    movi v9.16b, #0
    movi v10.16b, #0
    movi v11.16b, #0
    movi v12.16b, #0
    movi v13.16b, #0
    movi v14.16b, #0
    movi v15.16b, #0
    movi v16.16b, #0
    movi v17.16b, #0
    movi v18.16b, #0
    movi v19.16b, #0
    movi v20.16b, #0
    movi v21.16b, #0
    movi v22.16b, #0
    movi v23.16b, #0
    movi v24.16b, #0
    movi v25.16b, #0
    movi v26.16b, #0
    movi v27.16b, #0
    movi v28.16b, #0
    movi v29.16b, #0
    movi v30.16b, #0
    movi v31.16b, #0
    ic iallu
    dsb sy
    isb
    /*
     * A runtime built for the t8110 SEPROM takes its handoff pointer from
     * here rather than from x0, with bit zero as the cold-boot flag; see
     * boot_platform.c.  Zero leaves the register alone.
     */
    cbz x26, 1f
    msr s3_7_c15_c2_0, x26
    isb
1:
    mov x0, x28
    mov x1, x27
    mov x30, x29
    mov x26, xzr
    mov x27, xzr
    mov x28, xzr
    mov x29, xzr
    ret
.size sep_boot_scrub_architectural_state_and_enter_runtime, .-sep_boot_scrub_architectural_state_and_enter_runtime

.global sep_runtime_set_stacks_and_enter
.type sep_runtime_set_stacks_and_enter,@function
sep_runtime_set_stacks_and_enter:
    movz x1, #0x8000
    movk x1, #0x0403, lsl #16
    mov sp, x1
    msr spsel, #0
    movz x1, #0x0403, lsl #16
    isb
    mov sp, x1
    adrp x10, sep_exception_current_el_sp0_sync
    add x10, x10, :lo12:sep_exception_current_el_sp0_sync
    msr vbar_el1, x10
    isb
    mrs x0, cpacr_el1
    orr x0, x0, #0x300000
    msr cpacr_el1, x0
    isb
    bl sep_runtime_copy_initialized_data
    bl sep_runtime_clear_regions
    bl sep_main_initialize
    b sep_early_runtime_halt_loop
.size sep_runtime_set_stacks_and_enter, .-sep_runtime_set_stacks_and_enter

.global sep_exception_validate_stack_pointer
.type sep_exception_validate_stack_pointer,@function
sep_exception_validate_stack_pointer:
    mov x9, sp
    movz x10, #0x4000
    movk x10, #0x0402, lsl #16
    cmp x9, x10
    b.ls .Lcheck_high_exception_stack
    movz x10, #0xc000
    movk x10, #0x0402, lsl #16
    cmp x9, x10
    b.ls .Lvalid_exception_stack
.Lcheck_high_exception_stack:
    movz x10, #0xc000
    movk x10, #0x0402, lsl #16
    cmp x9, x10
    b.ls .Linvalid_exception_stack
    movz x10, #0x0403, lsl #16
    cmp x9, x10
    b.ls .Lvalid_exception_stack
.Linvalid_exception_stack:
    wfe
    b .Linvalid_exception_stack
.Lvalid_exception_stack:
    ret
.size sep_exception_validate_stack_pointer, .-sep_exception_validate_stack_pointer

.section .text.open_secure_rom_exception_vectors,"ax",@progbits
.balign 0x80
.global sep_exception_current_el_sp0_sync
.type sep_exception_current_el_sp0_sync,@function
sep_exception_current_el_sp0_sync:
    msr spsel, #0
    isb
    sub sp, sp, #832
    stp x0, x1, [sp, #56]
    add x0, sp, #832
    str x0, [sp, #16]
    stp x29, x30, [sp]
    bl sep_exception_validate_stack_pointer
    ldp x0, x1, [sp, #56]
    ldp x29, x30, [sp]
    mrs x30, elr_el1
    mov x0, sp
    mrs x1, esr_el1
    str x1, [x0, #48]
    mrs x1, far_el1
    str x1, [x0, #40]
    adrp x1, sep_exception_handle_sync
    add x1, x1, :lo12:sep_exception_handle_sync
    b sep_exception_dispatch
.size sep_exception_current_el_sp0_sync, .-sep_exception_current_el_sp0_sync

.balign 0x80
.global sep_exception_current_el_sp0_irq
.type sep_exception_current_el_sp0_irq,@function
sep_exception_current_el_sp0_irq:
    msr spsel, #0
    isb
    sub sp, sp, #832
    stp x0, x1, [sp, #56]
    add x0, sp, #832
    str x0, [sp, #16]
    stp x29, x30, [sp]
    bl sep_exception_validate_stack_pointer
    ldp x0, x1, [sp, #56]
    ldp x29, x30, [sp]
    mrs x30, elr_el1
    mov x0, sp
.Lirq_terminal:
    wfe
    b .Lirq_terminal
.size sep_exception_current_el_sp0_irq, .-sep_exception_current_el_sp0_irq

.balign 0x80
.global sep_exception_current_el_sp0_fiq
.type sep_exception_current_el_sp0_fiq,@function
sep_exception_current_el_sp0_fiq:
    msr spsel, #0
    isb
    sub sp, sp, #832
    stp x0, x1, [sp, #56]
    add x0, sp, #832
    str x0, [sp, #16]
    stp x29, x30, [sp]
    bl sep_exception_validate_stack_pointer
    ldp x0, x1, [sp, #56]
    ldp x29, x30, [sp]
    mrs x30, elr_el1
    mov x0, sp
.Lfiq_terminal:
    wfe
    b .Lfiq_terminal
.size sep_exception_current_el_sp0_fiq, .-sep_exception_current_el_sp0_fiq

.balign 0x80
.global sep_exception_current_el_sp0_serror
.type sep_exception_current_el_sp0_serror,@function
sep_exception_current_el_sp0_serror:
    msr spsel, #0
    isb
    sub sp, sp, #832
    stp x0, x1, [sp, #56]
    add x0, sp, #832
    str x0, [sp, #16]
    stp x29, x30, [sp]
    bl sep_exception_validate_stack_pointer
    ldp x0, x1, [sp, #56]
    ldp x29, x30, [sp]
    mrs x30, elr_el1
    mov x0, sp
    mrs x1, esr_el1
    str x1, [x0, #48]
    mrs x1, far_el1
    str x1, [x0, #40]
    adrp x1, sep_exception_handle_serror
    add x1, x1, :lo12:sep_exception_handle_serror
    b sep_exception_dispatch
.size sep_exception_current_el_sp0_serror, .-sep_exception_current_el_sp0_serror

.p2align 2
.global sep_exception_dispatch
.type sep_exception_dispatch,@function
sep_exception_dispatch:
    mrs x2, spsr_el1
    str w2, [x0, #24]
    mrs x30, elr_el1
    .arch_extension pauth
    pacib x30, x0
    str x30, [x0, #32]
    mov x21, x0
    blr x1
.Ldispatch_terminal:
    wfe
    b .Ldispatch_terminal
.size sep_exception_dispatch, .-sep_exception_dispatch

/*
 * The current-EL SPx half of the table, which had no entries at all.
 *
 * The runtime runs on SP0, so these are reached only by an exception taken
 * while SP_EL1 was selected -- a fault inside an exception entry before its
 * `msr spsel, #0`, or code that switched itself.  With nothing here, VBAR+0x200
 * was whatever function the linker put next (sep_aes_key_length_bytes) and the
 * core stopped there with no record: measured on a 23A341 restore,
 * `load_sep_os`, SEP PC 0x2004200, EL1h, the kernel left waiting for an ack.
 * Each entry goes to its SP0 twin, which moves to SP0 itself, so the record is
 * built and mailed the same way.  The SP0 entries above, and their
 * addresses, are unchanged.
 */
.balign 0x80
.global sep_exception_current_el_spx_sync
sep_exception_current_el_spx_sync:
    b sep_exception_current_el_sp0_sync
.balign 0x80
.global sep_exception_current_el_spx_irq
sep_exception_current_el_spx_irq:
    b sep_exception_current_el_sp0_irq
.balign 0x80
.global sep_exception_current_el_spx_fiq
sep_exception_current_el_spx_fiq:
    b sep_exception_current_el_sp0_fiq
.balign 0x80
.global sep_exception_current_el_spx_serror
sep_exception_current_el_spx_serror:
    b sep_exception_current_el_sp0_serror

.text
.p2align 2
.global open_secure_rom_runtime_authentication_verify_fallthrough
.type open_secure_rom_runtime_authentication_verify_fallthrough,@function
open_secure_rom_runtime_authentication_verify_fallthrough:
    bl sep_platform_runtime_authentication_verify_or_panic
    ret
.size open_secure_rom_runtime_authentication_verify_fallthrough, .-open_secure_rom_runtime_authentication_verify_fallthrough
