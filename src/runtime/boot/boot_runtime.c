#include "open_secure_rom/boot_handoff.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"
#include "open_secure_rom/runtime_storage.h"

extern sep_u8 __data_load_start[];
extern sep_u8 __data_start[];
extern sep_u8 __data_end[];

void sep_boot_prepare_runtime_mapping(sep_u32 runtime_mode) {
    sep_platform_transition_stage_noop(7);
    sep_runtime_configure_mapping_for_mode(runtime_mode);
}

void __attribute__((noreturn))
sep_boot_prepare_runtime_mapping_and_panic_on_return(
    sep_u32 runtime_mode
) {
    sep_boot_prepare_runtime_mapping(runtime_mode);
    sep_protocol_event_log_append(0x10009);
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_early_runtime_halt_loop(void) {
    for (;;) {
        __asm__ volatile("wfi\n\twfe" ::: "memory");
    }
}

void sep_runtime_copy_initialized_data(void) {
    sep_memmove(
        __data_start,
        __data_load_start,
        (sep_size_t)(__data_end - __data_start)
    );
}
