#ifndef OPEN_SECURE_ROM_RUNTIME_H
#define OPEN_SECURE_ROM_RUNTIME_H

#include "open_secure_rom/types.h"

void *sep_memzero(void *destination, sep_size_t length);
void *sep_memset(void *destination, int value, sep_size_t length);
void *sep_memmove(void *destination, const void *source, sep_size_t length);
void *memcpy(void *destination, const void *source, sep_size_t length);
sep_bool sep_buffer_has_nonzero_byte(const void *buffer, sep_size_t length);
int sep_constant_time_memcmp(const void *left, const void *right, sep_size_t length);
int sep_constant_time_memcmp_veneer(
    const void *left,
    const void *right,
    sep_size_t length
);
int sep_memset_checked(
    void *destination,
    sep_size_t destination_size,
    int value,
    sep_size_t count,
    sep_size_t object_size
);
void *sep_memmove_checked(
    void *destination,
    const void *source,
    sep_size_t length,
    sep_size_t destination_size
);
void *sep_memmove_qwords(
    sep_size_t qword_count,
    void *destination,
    const void *source
);
void *sep_memzero_via_runtime(sep_size_t length, void *destination);
sep_u64 sep_xorshift64_next(void);
void sep_platform_runtime_barrier_noop(void);
void sep_configure_timer_event_stream(void);
void sep_disable_el0_system_controls(void);
void sep_dcache_clean_invalidate_range(const void *address, sep_size_t length);
void sep_dcache_maintain_range(
    const void *address,
    sep_size_t length,
    sep_bool invalidate_after_clean
);
void sep_tlb_invalidate_range_or_all(sep_u64 virtual_address, sep_size_t length);
sep_u64 sep_read_cntpct_synchronized(void);
void sep_icache_invalidate_all(void);
void sep_icache_invalidate_by_va(const void *address);
void sep_dcache_clean_by_va(const void *address);
void sep_dcache_invalidate_by_va(const void *address);
void sep_dcache_clean_invalidate_by_va(const void *address);
void sep_set_sctlr_el1_enib(sep_bool enabled);
void sep_write_apibkey_el1(sep_u64 high, sep_u64 low);
void sep_write_prediction_restriction_keys_el1(
    sep_u64 a_low,
    sep_u64 a_high,
    sep_u64 b_low,
    sep_u64 b_high
);
void sep_platform_counter_initialize(void);
sep_u64 sep_cntpct_ticks_from_microseconds(sep_u64 microseconds);
sep_u64 sep_read_time_microseconds(void);
void sep_wait_until_cntpct(sep_u64 deadline);
void sep_delay_microseconds(sep_u32 microseconds);
void sep_platform_transition_stage_noop(sep_u32 stage);
void sep_wait_for_event_once_synchronized(void);
void __attribute__((noreturn)) sep_fatal_wait_loop(void);
void sep_chkstk_darwin(void);
void sep_chkstk_darwin_probe_veneer(void);

#endif
