#ifndef OPEN_SECURE_ROM_WRAK_H
#define OPEN_SECURE_ROM_WRAK_H

#include "open_secure_rom/types.h"

sep_u32 sep_wrak_autk_read_result_word(sep_size_t byte_offset);
void sep_wrak_autk_stage_research_pattern(void);
void sep_wrak_autk_install_autp_material(
    const sep_u8 material[28],
    sep_u64 slot_group
);
void sep_wrak_autk_install_labeled_key_material(
    const sep_u8 material[28],
    sep_u32 selector,
    const char *label
);
void sep_wrak_autk_commit_research_pattern(void);
sep_bool sep_wrak_autk_buffer_has_nonzero_byte(
    const void *buffer,
    sep_size_t length
);
void sep_wrak_autk_apply_selector_to_all_providers(sep_u32 selector);
void sep_wrak_autk_apply_selector_to_provider(
    sep_u32 selector,
    sep_u8 provider_index
);
void sep_wrak_autk_install_autp_provider_noop(
    const sep_u8 material[28],
    sep_u8 provider_index
);
void sep_wrak_autk_import_type7_record(void);
sep_bool sep_wrak_autk_load_authenticated_record_material(
    sep_u8 record_type,
    sep_u8 output[28]
);
void sep_wrak_autk_derive_and_install_from_type8_record(void);

#ifdef OPEN_SECURE_ROM_HOST_TEST
sep_u8 *open_secure_rom_wrak_test_state(void);
#endif

#endif
