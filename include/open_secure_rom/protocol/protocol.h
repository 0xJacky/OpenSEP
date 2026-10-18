#ifndef OPEN_SECURE_ROM_PROTOCOL_H
#define OPEN_SECURE_ROM_PROTOCOL_H

#include "open_secure_rom/types.h"

typedef struct sep_protocol_dispatch_result {
    sep_mailbox_slot_t response;
    sep_bool has_response;
    sep_u32 phase;
    sep_u64 shared_region_base;
    sep_u8 shared_region_mode;
} sep_protocol_dispatch_result_t;

void *sep_fill_research_seed_pattern(void *buffer, sep_size_t length);
sep_bool sep_research_seed_is_initialized(void);
sep_bool sep_initialize_research_seed(void);
void sep_clear_research_seed(void);
sep_optional_research_seed_t sep_get_optional_research_seed(void);
sep_bool sep_optional_research_seed_is_present(
    const sep_optional_research_seed_t *value
);
const sep_optional_research_seed_t *sep_optional_research_seed_require_present(
    const sep_optional_research_seed_t *value
);
void sep_clear_research_value64(void);
sep_bool sep_initialize_research_value64(void);
sep_bool sep_research_value64_is_initialized(void);
void sep_require_initialized_research_value64(void);
sep_optional_research_value64_t sep_get_optional_research_value64(void);
sep_optional_research_value64_t sep_optional_research_value64_from_bytes(
    const void *bytes,
    sep_size_t length
);
void sep_optional_research_value64_initialize_from_bytes(
    sep_optional_research_value64_t *result,
    const void *bytes,
    sep_size_t length
);
sep_bool sep_optional_research_value64_is_present(
    const sep_optional_research_value64_t *value
);
const sep_optional_research_value64_t *
sep_optional_research_value64_require_present(
    const sep_optional_research_value64_t *value
);
void open_secure_rom_protocol_phase_reset(void);
sep_u32 open_secure_rom_protocol_phase(void);
sep_mailbox_slot_t sep_protocol_build_response(
    sep_u8 sequence,
    sep_u8 tag,
    sep_u8 argument,
    sep_u32 payload
);
sep_protocol_dispatch_result_t sep_protocol_dispatch_request(sep_u64 request);

#endif
