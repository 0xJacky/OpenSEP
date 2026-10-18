#include "open_secure_rom/runtime/boot/bootstrap.h"

.text
.p2align 2
.global sep_runtime_clear_regions
.type sep_runtime_clear_regions,@function
sep_runtime_clear_regions:
    /* The active SP_EL0 is the upper bound of the first cleared region. */
    ldr x0, =SEP_BOOT_EL0_STACK_BOTTOM
    ldr x1, =SEP_BOOT_EL0_STACK_TOP
.Lclear_el0_stack:
    stp xzr, xzr, [x0], #16
    cmp x0, x1
    b.lo .Lclear_el0_stack

    ldr x0, =SEP_BOOT_EL1_STACK_BOTTOM
    ldr x1, =SEP_BOOT_EL1_STACK_TOP
.Lclear_el1_stack:
    stp xzr, xzr, [x0], #16
    cmp x0, x1
    b.lo .Lclear_el1_stack

    ldr x0, =SEP_BOOT_RUNTIME_CLEAR_BASE
    ldr x1, =SEP_BOOT_RUNTIME_CLEAR_LIMIT
.Lclear_runtime_state:
    stp xzr, xzr, [x0], #16
    cmp x0, x1
    b.lo .Lclear_runtime_state
    ret
.size sep_runtime_clear_regions, .-sep_runtime_clear_regions
