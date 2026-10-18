#ifndef OPEN_SECURE_ROM_CONFIGURATION_SINK_H
#define OPEN_SECURE_ROM_CONFIGURATION_SINK_H

#include "open_secure_rom/types.h"

sep_bool sep_optional_configuration_key48_is_present(
    const sep_optional_configuration_key48_t *value
);
const sep_optional_configuration_key48_t *
sep_optional_configuration_key48_require_present(
    const sep_optional_configuration_key48_t *value
);
void sep_optional_configuration_key48_initialize_from_data(
    sep_optional_configuration_key48_t *output,
    const void *data,
    sep_size_t length
);
void sep_write_configuration_key_sink(
    const sep_optional_configuration_key48_t *material,
    sep_bool include_material,
    sep_u32 configuration_word
);
void sep_write_context_configuration_key_sink(
    const void *context,
    sep_bool include_material
);

#endif
