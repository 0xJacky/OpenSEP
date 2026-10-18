#include "open_secure_rom/runtime_storage.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/runtime.h"
#include "open_secure_rom/runtime_handoff.h"

enum {
    SEP_RUNTIME_REGION_COUNT = 8,
};

static sep_address_range_t runtime_regions[SEP_RUNTIME_REGION_COUNT]
    OPEN_SECURE_ROM_SECTION(".runtime_regions");

static struct {
    sep_bool contiguous_l3_active;
    sep_bool region_mapping_active;
    sep_bool mode_mapping_active;
} runtime_mapping_state
    OPEN_SECURE_ROM_SECTION(".runtime_mapping_state")
    __attribute__((used));

static const sep_u64 runtime_mode_region_offsets[6] = {
    0,
    0,
    0,
    0x06000000,
    0,
    0x06000000,
};

static const sep_u8 runtime_region_kind_indices[6] = {
    2,
    0,
    3,
    1,
    6,
    4,
};

static const sep_u64 runtime_region_virtual_bases[6] = {
    0,
    0,
    0,
    0x0800000000ULL,
    0,
    0x0800000000ULL,
};

/* Region kinds 1 and 3 to 6 are valid; kind 2 and anything else is fatal. */
static sep_u32 runtime_region_kind_index_checked(sep_u32 region_kind) {
    const sep_u32 kind_index = region_kind - 1;
    if (kind_index > 5 || ((0x3dU >> kind_index) & 1) == 0) {
        sep_fatal_wait_loop();
    }
    return kind_index;
}

#ifdef OPEN_SECURE_ROM_HOST_TEST
static sep_u64 host_l2_entries[0x800];
static sep_u64 host_l3_entries[0x800];
static sep_u64 host_low_runtime_entries[0x1000];
static sep_u64 host_high_runtime_entries[0x1000];
#endif

sep_size_t sep_address_range_length(const sep_address_range_t *range) {
    if (range == 0 || ((uintptr_t)range & 7) != 0 || range->end < range->start) {
        sep_fatal_wait_loop();
    }
    return range->end - range->start;
}

sep_size_t sep_runtime_region_table_length(sep_size_t table_index) {
    if (table_index >= SEP_RUNTIME_REGION_COUNT) {
        sep_fatal_wait_loop();
    }
    return sep_address_range_length(&runtime_regions[table_index]);
}

sep_size_t sep_runtime_region_get_layout(
    sep_u64 *base,
    sep_size_t *length,
    sep_u32 region_kind
) {
    if (base == 0 || length == 0 || ((uintptr_t)base & 7) != 0 ||
        ((uintptr_t)length & 7) != 0) {
        sep_fatal_wait_loop();
    }

    const sep_u32 kind_index = runtime_region_kind_index_checked(region_kind);
    *base = runtime_region_virtual_bases[kind_index];
    *length = sep_runtime_region_table_length(
        runtime_region_kind_indices[kind_index]
    );
    if (*length > 0x02000000) {
        sep_fatal_wait_loop();
    }
    return *length;
}

sep_u64 sep_make_stage1_page_descriptor(
    sep_u64 physical_address,
    sep_size_t mapping_size,
    sep_u32 access_permissions,
    sep_bool non_secure,
    sep_u32 memory_attribute_index,
    sep_bool executable
) {
    if ((physical_address >> 42) != 0 ||
        ((mapping_size + 0x03ffffffffffULL) & physical_address) != 0 ||
        memory_attribute_index >= 8) {
        sep_fatal_wait_loop();
    }

    sep_u64 descriptor = mapping_size == 0x4000 ? 3 : 1;
    descriptor |= (sep_u64)memory_attribute_index << 2;
    descriptor |= physical_address;
    if (non_secure == 1) {
        descriptor |= 0x20;
    }
    descriptor |= (sep_u64)access_permissions << 6;
    descriptor |= executable ? 0x600 : 0x0060000000000600ULL;
    return descriptor;
}

sep_u64 *sep_runtime_page_table_entry_for_va(sep_u64 virtual_address) {
    const sep_u64 region = virtual_address & 0xfffffffffe000000ULL;
    if (region != 0x02000000 && region != 0x04000000) {
        sep_fatal_wait_loop();
    }
    if ((virtual_address & 0x3fff) != 0) {
        sep_fatal_wait_loop();
    }
#ifdef OPEN_SECURE_ROM_HOST_TEST
    sep_u64 *entries = region == 0x02000000
        ? host_low_runtime_entries
        : host_high_runtime_entries;
    return &entries[(virtual_address - region) >> 14];
#else
    const sep_u64 table_base = region == 0x02000000 ? 0x04058000 : 0x04060000;
    return (sep_u64 *)(table_base + ((virtual_address - region) >> 11));
#endif
}

void sep_runtime_map_page(
    sep_u64 virtual_address,
    sep_u64 physical_address,
    sep_u32 access_permissions,
    sep_bool non_secure,
    sep_u32 memory_attribute_index,
    sep_bool executable
) {
    if ((physical_address & 0x3fff) != 0) {
        sep_fatal_wait_loop();
    }
    *sep_runtime_page_table_entry_for_va(virtual_address) =
        sep_make_stage1_page_descriptor(
            physical_address,
            0x4000,
            access_permissions,
            non_secure,
            memory_attribute_index,
            executable
        );
    sep_tlb_invalidate_range_or_all(virtual_address, 0x4000);
}

void sep_runtime_unmap_page(sep_u64 virtual_address) {
    *sep_runtime_page_table_entry_for_va(virtual_address) = 0;
    sep_tlb_invalidate_range_or_all(virtual_address, 0x4000);
}

sep_u64 *sep_runtime_l2_entry_for_va(sep_u64 virtual_address) {
    if ((virtual_address & 0x01ffffff) != 0) {
        sep_fatal_wait_loop();
    }
#ifdef OPEN_SECURE_ROM_HOST_TEST
    return &host_l2_entries[virtual_address >> 25];
#else
    return (sep_u64 *)(0x04054000 + (virtual_address >> 22));
#endif
}

sep_u64 *sep_runtime_l3_entry_for_va(sep_u64 virtual_address) {
    if ((virtual_address & 0x3fff) != 0) {
        sep_fatal_wait_loop();
    }
#ifdef OPEN_SECURE_ROM_HOST_TEST
    return &host_l3_entries[(virtual_address >> 14) & 0x7ff];
#else
    return (sep_u64 *)(0x0405c000 | ((virtual_address >> 11) & 0x3ff8));
#endif
}

void sep_runtime_region_map_pages(
    sep_u32 region_kind,
    sep_size_t length
) {
    if (runtime_mapping_state.region_mapping_active ||
        runtime_mapping_state.mode_mapping_active == 1) {
        sep_fatal_wait_loop();
    }
    runtime_mapping_state.region_mapping_active = 1;
    if (length > 0x02000000) {
        sep_fatal_wait_loop();
    }

    const sep_u32 kind_index = runtime_region_kind_index_checked(region_kind);
    sep_u64 virtual_address = runtime_region_virtual_bases[kind_index];
    sep_u64 physical_address = 0;
    if (region_kind == 4) {
        physical_address = sep_runtime_region_mode_base(1, 4);
    } else if (region_kind == 6) {
        physical_address = sep_runtime_region_mode_base(4, 6);
    }
    sep_runtime_map_contiguous_region(
        virtual_address,
        physical_address,
        length,
        1,
        0
    );
    sep_platform_runtime_mapping_commit();
}

void sep_runtime_region_unmap_pages(
    sep_u32 region_kind,
    sep_size_t length
) {
    if (runtime_mapping_state.region_mapping_active != 1 ||
        runtime_mapping_state.mode_mapping_active == 1) {
        sep_fatal_wait_loop();
    }
    runtime_mapping_state.region_mapping_active = 0;
    if (length > 0x02000000) {
        sep_fatal_wait_loop();
    }
    const sep_u32 kind_index = runtime_region_kind_index_checked(region_kind);
    sep_runtime_unmap_contiguous_region(
        runtime_region_virtual_bases[kind_index],
        length
    );
}

void sep_runtime_region_map(sep_u32 region_kind) {
    const sep_u32 kind_index = runtime_region_kind_index_checked(region_kind);
    const sep_size_t length = sep_runtime_region_table_length(
        runtime_region_kind_indices[kind_index]
    );
    sep_runtime_region_map_pages(region_kind, length);
}

void sep_runtime_region_unmap(sep_u32 region_kind) {
    const sep_u32 kind_index = runtime_region_kind_index_checked(region_kind);
    const sep_size_t length = sep_runtime_region_table_length(
        runtime_region_kind_indices[kind_index]
    );
    const sep_u64 virtual_address = runtime_region_virtual_bases[kind_index];
#ifndef OPEN_SECURE_ROM_HOST_TEST
    __asm__ volatile("dsb sy" ::: "memory");
#endif
    sep_dcache_clean_invalidate_range(
        (const void *)(uintptr_t)virtual_address,
        length
    );
    sep_runtime_region_unmap_pages(region_kind, length);
}

void sep_runtime_configure_mapping_for_mode(sep_u32 runtime_mode) {
    if (runtime_mapping_state.region_mapping_active ||
        runtime_mapping_state.mode_mapping_active == 1) {
        sep_fatal_wait_loop();
    }
    runtime_mapping_state.mode_mapping_active = 1;

    sep_u64 virtual_address = 0;
    sep_u64 physical_address = 0;
    sep_size_t length;
    if (runtime_mode == 4) {
        length = sep_runtime_region_length_checked(1);
        virtual_address = 0x0800000000ULL;
        physical_address = sep_runtime_region_mode_base(1, 4);
    } else if (runtime_mode == 3) {
        length = sep_runtime_region_length_checked(3);
    } else if (runtime_mode == 1) {
        length = sep_runtime_region_length_checked(2);
    } else {
        sep_fatal_wait_loop();
    }
    if (length > 0x02000000) {
        sep_fatal_wait_loop();
    }
    sep_runtime_map_contiguous_region(
        virtual_address,
        physical_address,
        length,
        1,
        1
    );
}

void sep_runtime_map_contiguous_region(
    sep_u64 virtual_address,
    sep_u64 physical_address,
    sep_size_t length,
    sep_u32 memory_attribute_index,
    sep_bool executable
) {
    if (runtime_mapping_state.contiguous_l3_active ||
        (length & 0x3fff) != 0) {
        sep_fatal_wait_loop();
    }

    sep_size_t block_count = length >> 25;
    const sep_size_t page_count = (length >> 14) & 0x7ff;
    sep_u64 current_virtual = virtual_address;
    while (block_count != 0) {
        *sep_runtime_l2_entry_for_va(current_virtual) =
            sep_make_stage1_page_descriptor(
                physical_address,
                0x02000000,
                0,
                0,
                memory_attribute_index,
                executable
            );
        if (physical_address > UINT64_MAX - 0x02000000 ||
            current_virtual > UINT64_MAX - 0x02000000) {
            sep_fatal_wait_loop();
        }
        physical_address += 0x02000000;
        current_virtual += 0x02000000;
        --block_count;
    }

    if (page_count != 0) {
        sep_u64 *entry = sep_runtime_l3_entry_for_va(current_virtual);
        for (sep_size_t index = 0; index < page_count; ++index) {
            const sep_u64 page_offset = index << 14;
            if (physical_address > UINT64_MAX - page_offset) {
                sep_fatal_wait_loop();
            }
            entry[index] = sep_make_stage1_page_descriptor(
                physical_address + page_offset,
                0x4000,
                0,
                0,
                memory_attribute_index,
                executable
            );
        }
        sep_memzero(
            entry + page_count,
            0x4000 - page_count * sizeof(*entry)
        );
        *sep_runtime_l2_entry_for_va(current_virtual) = 0x04048003;
        runtime_mapping_state.contiguous_l3_active = 1;
    }
    sep_tlb_invalidate_range_or_all(virtual_address, length);
}

void sep_runtime_unmap_contiguous_region(
    sep_u64 virtual_address,
    sep_size_t length
) {
    if ((length & 0x3fff) != 0 || length > UINT64_MAX - 0x01ffffff) {
        sep_fatal_wait_loop();
    }
    sep_size_t block_count = (length + 0x01ffffff) >> 25;
    sep_u64 current_virtual = virtual_address;
    while (block_count != 0) {
        *sep_runtime_l2_entry_for_va(current_virtual) = 0;
        if (current_virtual > UINT64_MAX - 0x02000000) {
            sep_fatal_wait_loop();
        }
        current_virtual += 0x02000000;
        --block_count;
    }
    sep_tlb_invalidate_range_or_all(virtual_address, length);
    runtime_mapping_state.contiguous_l3_active = 0;
}

const sep_address_range_t *sep_runtime_region_at_checked(
    sep_u32 region_index
) {
    if (region_index >= SEP_RUNTIME_REGION_COUNT) {
        sep_fatal_wait_loop();
    }
    return &runtime_regions[region_index];
}

sep_size_t sep_runtime_region_length_checked(sep_u32 region_index) {
    return sep_address_range_length(
        sep_runtime_region_at_checked(region_index)
    );
}

sep_u64 sep_runtime_mode_region_offset(sep_u32 runtime_mode) {
    const sep_u32 index = runtime_mode - 1;
    if (index > 5 || ((0x3dU >> index) & 1) == 0) {
        sep_fatal_wait_loop();
    }
    return runtime_mode_region_offsets[index];
}

sep_u64 sep_runtime_region_mode_base(
    sep_u32 region_index,
    sep_u32 runtime_mode
) {
    const sep_u64 start = sep_runtime_region_at_checked(region_index)->start;
    const sep_u64 offset = sep_runtime_mode_region_offset(runtime_mode);
    if (start > UINT64_MAX - offset) {
        sep_fatal_wait_loop();
    }
    return start + offset;
}

int sep_checked_bytes20_compare(
    const sep_checked_bytes20_t *left,
    const sep_checked_bytes20_t *right
) {
    if (left->initialized != 1 || right->initialized != 1) {
        sep_fatal_wait_loop();
    }
    return sep_constant_time_memcmp_veneer(
        left->bytes,
        right->bytes,
        sizeof(left->bytes)
    );
}

sep_bool sep_checked_bytes20_equal(
    const sep_checked_bytes20_t *left,
    const sep_checked_bytes20_t *right
) {
    return sep_checked_bytes20_compare(left, right) == 0;
}

void sep_runtime_region_prepare_zeroing_hook(sep_u32 region_kind) {
    (void)region_kind;
}

void sep_runtime_region_table_reset(void) {
    sep_platform_wrak_autk_slot_count();
    sep_platform_runtime_region_table_reset_status();
    runtime_regions[0] = (sep_address_range_t){0, 0};
    ((sep_u8 *)&runtime_regions[7].start)[0] = 1;
}

void sep_runtime_region_table_set(
    sep_u8 table_index,
    sep_u64 start,
    sep_u64 end
) {
    if (end < start || table_index >= SEP_RUNTIME_REGION_COUNT) {
        sep_fatal_wait_loop();
    }
    runtime_regions[table_index] = (sep_address_range_t){start, end};
}

void sep_runtime_region_table_initialize(sep_u32 region_size_kib) {
    sep_runtime_region_table_reset();
    if (region_size_kib == 0 || region_size_kib > 0x8000) {
        sep_fatal_wait_loop();
    }
    if ((region_size_kib & 0x0f) != 0) {
        sep_protocol_event_log_append(0x80040008);
        sep_fatal_wait_loop();
    }
    sep_runtime_region_table_set(
        1,
        0,
        ((const sep_u8 *)&runtime_regions[7].start)[0] != 0
            ? 0x02000000
            : 0
    );
    sep_runtime_region_table_set(4, 0, 0);
}

void sep_runtime_prepare_zeroed_regions(sep_u32 region_size_kib) {
    if (region_size_kib == 0) {
        sep_protocol_event_log_append(0x80040011);
        sep_panic_with_reason_and_pc(
            0x59,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }

    sep_runtime_region_table_initialize(region_size_kib);
    sep_u64 region3_base = 0;
    sep_size_t region3_length = 0;
    sep_runtime_region_get_layout(&region3_base, &region3_length, 3);
    sep_u64 region1_base = 0;
    sep_size_t region1_length = 0;
    sep_runtime_region_get_layout(&region1_base, &region1_length, 1);
    sep_u64 region5_base = 0;
    sep_size_t region5_length = 0;
    sep_runtime_region_get_layout(&region5_base, &region5_length, 5);

    sep_platform_seed_runtime_mode_configuration_blocks(1);
    sep_runtime_mode_configuration_complete_hook(1);
    if (region5_length != 0) {
        sep_platform_seed_runtime_mode_configuration_blocks(4);
        sep_runtime_mode_configuration_complete_hook(4);
        sep_runtime_region_prepare_zeroing_hook(6);
        sep_runtime_region_map(5);
        sep_memzero((void *)(uintptr_t)region5_base, region5_length);
        sep_runtime_region_unmap(5);
    } else {
        sep_u64 region6_base = 0;
        sep_size_t region6_length = 0;
        sep_runtime_region_get_layout(&region6_base, &region6_length, 6);
        if (region6_length != 0) {
            sep_runtime_region_map(6);
            sep_memzero((void *)(uintptr_t)region6_base, region6_length);
            sep_runtime_region_unmap(6);
        }
    }

    if (region3_length != 0) {
        sep_runtime_region_prepare_zeroing_hook(3);
        sep_runtime_region_map(3);
        sep_runtime_region_get_layout(&region3_base, &region3_length, 3);
        sep_memzero((void *)(uintptr_t)region3_base, region3_length);
    }
    if (region1_length != 0) {
        if (region3_length != 0) {
            sep_runtime_region_unmap(3);
        }
        sep_runtime_region_prepare_zeroing_hook(2);
        sep_runtime_region_map(1);
        sep_runtime_region_get_layout(&region1_base, &region1_length, 1);
        sep_memzero((void *)(uintptr_t)region1_base, region1_length);
    }
}
