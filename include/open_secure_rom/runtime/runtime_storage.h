#ifndef OPEN_SECURE_ROM_RUNTIME_STORAGE_H
#define OPEN_SECURE_ROM_RUNTIME_STORAGE_H

#include "open_secure_rom/types.h"

sep_size_t sep_address_range_length(const sep_address_range_t *range);
sep_size_t sep_runtime_region_get_layout(
    sep_u64 *base,
    sep_size_t *length,
    sep_u32 region_kind
);
sep_size_t sep_runtime_region_table_length(sep_size_t table_index);
sep_u64 sep_make_stage1_page_descriptor(
    sep_u64 physical_address,
    sep_size_t mapping_size,
    sep_u32 access_permissions,
    sep_bool non_secure,
    sep_u32 memory_attribute_index,
    sep_bool executable
);
void sep_runtime_map_page(
    sep_u64 virtual_address,
    sep_u64 physical_address,
    sep_u32 access_permissions,
    sep_bool non_secure,
    sep_u32 memory_attribute_index,
    sep_bool executable
);
sep_u64 *sep_runtime_page_table_entry_for_va(sep_u64 virtual_address);
void sep_runtime_unmap_page(sep_u64 virtual_address);
void sep_runtime_map_contiguous_region(
    sep_u64 virtual_address,
    sep_u64 physical_address,
    sep_size_t length,
    sep_u32 memory_attribute_index,
    sep_bool executable
);
void sep_runtime_unmap_contiguous_region(
    sep_u64 virtual_address,
    sep_size_t length
);
void sep_runtime_region_map(sep_u32 region_kind);
void sep_runtime_region_unmap(sep_u32 region_kind);
void sep_runtime_region_map_pages(
    sep_u32 region_kind,
    sep_size_t length
);
void sep_runtime_region_unmap_pages(
    sep_u32 region_kind,
    sep_size_t length
);
void sep_runtime_configure_mapping_for_mode(sep_u32 runtime_mode);
sep_u64 sep_runtime_region_mode_base(
    sep_u32 region_index,
    sep_u32 runtime_mode
);
sep_size_t sep_runtime_region_length_checked(sep_u32 region_index);
const sep_address_range_t *sep_runtime_region_at_checked(
    sep_u32 region_index
);
sep_u64 *sep_runtime_l2_entry_for_va(sep_u64 virtual_address);
sep_u64 *sep_runtime_l3_entry_for_va(sep_u64 virtual_address);
void sep_runtime_region_prepare_zeroing_hook(sep_u32 region_kind);
sep_bool sep_checked_bytes20_equal(
    const sep_checked_bytes20_t *left,
    const sep_checked_bytes20_t *right
);
int sep_checked_bytes20_compare(
    const sep_checked_bytes20_t *left,
    const sep_checked_bytes20_t *right
);
void sep_runtime_region_table_reset(void);
void sep_runtime_region_table_set(
    sep_u8 table_index,
    sep_u64 start,
    sep_u64 end
);
void sep_runtime_region_table_initialize(sep_u32 region_size_kib);
void sep_runtime_prepare_zeroed_regions(sep_u32 region_size_kib);
sep_u64 sep_runtime_mode_region_offset(sep_u32 runtime_mode);

#endif
