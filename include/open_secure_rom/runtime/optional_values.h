#ifndef OPEN_SECURE_ROM_OPTIONAL_VALUES_H
#define OPEN_SECURE_ROM_OPTIONAL_VALUES_H

#include "open_secure_rom/types.h"

sep_optional_u8_t sep_optional_u8_initialize_absent(void);
void sep_optional_u8_initialize_from_u32(
    sep_optional_u8_t *output,
    const sep_u32 *value
);
void sep_optional_u8_initialize_from_u64(
    sep_optional_u8_t *output,
    const sep_u64 *value
);
void sep_optional_u16_initialize_absent(sep_optional_u16_t *value);
void sep_optional_u16_initialize_absent_fields(sep_optional_u16_t *value);
void sep_optional_u16_initialize_from_u64(
    sep_optional_u16_t *output,
    const sep_u64 *value
);
void sep_optional_u64_initialize_absent(sep_optional_u64_t *value);
void sep_optional_u64_initialize_absent_fields(sep_optional_u64_t *value);
void sep_optional_u64_initialize_from_u64(
    sep_optional_u64_t *output,
    const sep_u64 *value
);
void sep_optional_bool_initialize_from_bool(
    sep_optional_bool_t *output,
    const sep_bool *value
);
sep_checked_bytes20_t sep_checked_bytes20_from_data(
    const sep_u8 *data,
    sep_size_t length
);
sep_checked_bytes48_t sep_checked_bytes48_from_data(
    const sep_u8 *data,
    sep_size_t length
);
int sep_checked_bytes48_compare(
    const sep_checked_bytes48_t *left,
    const sep_checked_bytes48_t *right
);
sep_bool sep_checked_bytes48_equal(
    const sep_checked_bytes48_t *left,
    const sep_checked_bytes48_t *right
);
sep_bool sep_optional_u8_matches_or_log(
    sep_u16 expected,
    sep_u16 actual,
    sep_u32 missing_event,
    sep_u32 mismatch_event
);
sep_bool sep_optional_bool_matches_or_log(
    sep_u16 expected,
    sep_u16 actual,
    sep_u32 missing_event,
    sep_u32 mismatch_event
);
void sep_optional_research_seed_initialize_from_data(
    sep_optional_research_seed_t *output,
    const void *data,
    sep_size_t length
);
sep_bool sep_checked_bytes32_any_nonzero(const sep_u8 bytes[32]);
int sep_checked_bytes32_compare_prefix(
    const sep_checked_bytes32_t *left,
    const sep_checked_bytes32_t *right,
    sep_size_t length
);
sep_checked_bytes32_t *sep_checked_bytes32_initialize(
    sep_checked_bytes32_t *output,
    const void *data,
    sep_size_t length
);
sep_checked_bytes32_t sep_checked_bytes32_from_data(
    const void *data,
    sep_size_t length
);
sep_optional_configuration_key48_t
sep_optional_configuration_key48_from_sha384(
    const void *data,
    sep_size_t length
);

#endif
