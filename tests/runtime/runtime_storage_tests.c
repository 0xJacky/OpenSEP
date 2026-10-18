#include "open_secure_rom/runtime_storage.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    return event_code;
}

void sep_platform_seed_runtime_mode_configuration_blocks(
    sep_u32 runtime_mode
) {
    (void)runtime_mode;
}

void __attribute__((noreturn)) sep_panic_with_reason_and_pc(
    sep_u32 reason,
    sep_u64 caller_pc
) {
    (void)reason;
    (void)caller_pc;
    sep_fatal_wait_loop();
}

void sep_tlb_invalidate_range_or_all(
    sep_u64 virtual_address,
    sep_size_t length
) {
    (void)virtual_address;
    (void)length;
}

void sep_platform_runtime_mapping_commit(void) {}

void sep_dcache_clean_invalidate_range(
    const void *address,
    sep_size_t length
) {
    (void)address;
    (void)length;
}

int main(void) {
    const sep_address_range_t range = {0x1000, 0x5000};
    assert(sep_address_range_length(&range) == 0x4000);

    sep_runtime_region_table_initialize(0x8000);
    assert(sep_runtime_region_table_length(1) == 0x02000000);
    sep_runtime_region_table_set(2, 0x100000, 0x104000);
    assert(sep_runtime_region_length_checked(2) == 0x4000);
    assert(sep_runtime_region_mode_base(2, 1) == 0x100000);
    assert(sep_runtime_region_mode_base(2, 4) == 0x06100000);

    sep_u64 base = 0;
    sep_size_t length = 0;
    assert(sep_runtime_region_get_layout(&base, &length, 1) == 0x4000);
    assert(base == 0);
    assert(length == 0x4000);

    const sep_u64 page = sep_make_stage1_page_descriptor(
        0x04000000,
        0x4000,
        1,
        0,
        2,
        1
    );
    assert(page == 0x0400064b);
    assert(sep_runtime_l2_entry_for_va(0) != 0);
    assert(sep_runtime_l3_entry_for_va(0) != 0);
    assert(sep_runtime_page_table_entry_for_va(0x02100000) != 0);
    sep_runtime_region_map(1);
    assert(*sep_runtime_l2_entry_for_va(0) != 0);
    sep_runtime_region_unmap(1);
    assert(*sep_runtime_l2_entry_for_va(0) == 0);
    sep_runtime_region_map_pages(4, 0x4000);
    assert(*sep_runtime_l3_entry_for_va(0x0800000000ULL) != 0);
    sep_runtime_region_unmap_pages(4, 0x4000);
    assert(*sep_runtime_l2_entry_for_va(0x0800000000ULL) == 0);
    sep_runtime_region_prepare_zeroing_hook(6);

    sep_checked_bytes20_t left = {.initialized = 1};
    sep_checked_bytes20_t right = {.initialized = 1};
    assert(sep_checked_bytes20_equal(&left, &right) == 1);
    right.bytes[19] = 1;
    assert(sep_checked_bytes20_equal(&left, &right) == 0);
    assert(sep_checked_bytes20_compare(&left, &right) < 0);
}
