#ifndef OPEN_SECURE_ROM_PROVISIONING_H
#define OPEN_SECURE_ROM_PROVISIONING_H

#include "open_secure_rom/types.h"

sep_u16 sep_crc16_update(
    const void *data,
    sep_size_t length,
    sep_u16 crc
);
sep_u64 *sep_platform_provisioning_cursor_store_checked(
    sep_u64 *destination,
    sep_u64 value
);
sep_bool sep_platform_provisioning_read_bytes_stub(
    void *provider,
    sep_u32 offset,
    sep_size_t length,
    void *output,
    sep_size_t output_capacity
);
sep_u64 *sep_platform_provisioning_limit_store_checked(
    sep_u64 *destination,
    sep_u64 value
);
sep_bool sep_platform_provisioning_provider_request_succeeds(
    const void *provider,
    sep_u64 request,
    sep_u64 argument
);
void sep_platform_provisioning_prepare_singleton(void);
void sep_platform_provisioning_state_prepare(
    sep_platform_provisioning_state_t *state
);
void sep_platform_provisioning_provider_clear(void);
sep_u64 *sep_platform_provisioning_provider_slot(void);
void sep_platform_provisioning_initialize(void);
sep_optional_configuration_key48_t
sep_platform_provisioning_get_optional_key48(void);
sep_optional_research_seed_t
sep_platform_provisioning_get_optional_research_seed(void);
sep_u64 *sep_platform_provisioning_record_zero_checked(sep_u64 *record);
void sep_platform_provisioning_record_clear(
    sep_u64 *records,
    sep_size_t index
);
sep_u32 sep_platform_provisioning_record_index_event_bits(
    sep_size_t record_index
);
void sep_platform_provisioning_record_store(
    sep_u64 *records,
    sep_size_t index,
    const sep_u64 *record
);
sep_bool sep_platform_provisioning_process_records(
    sep_platform_provisioning_state_t *state,
    sep_u8 record_type,
    sep_u64 callback_or_vtable_offset,
    sep_bool indirect_dispatch
);
sep_u64 sep_platform_provisioning_record_word_at(
    const sep_u64 *records,
    sep_size_t index
);
sep_bool sep_platform_provisioning_record_crc16_is_valid(
    sep_platform_provisioning_state_t *state,
    sep_size_t record_index
);
sep_platform_provisioning_state_t *sep_platform_provisioning_state_get(void);
void sep_platform_provisioning_state_reset(void);

#endif
