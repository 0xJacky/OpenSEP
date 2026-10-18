#include "open_secure_rom/configuration_sink.h"

#include "open_secure_rom/runtime.h"

enum {
    SEP_CONFIGURATION_KEY_SINK_WORDS = 16,
};

static volatile sep_u32 *open_secure_rom_configuration_sink_words(void) {
    return (volatile sep_u32 *)0x30600000ULL;
}

static volatile sep_u32 *open_secure_rom_configuration_sink_control(void) {
    return (volatile sep_u32 *)0x30600044ULL;
}

sep_bool sep_optional_configuration_key48_is_present(
    const sep_optional_configuration_key48_t *value
) {
    if (value == 0 || value->present >= 2) {
        sep_fatal_wait_loop();
    }
    return value->present;
}

const sep_optional_configuration_key48_t *
sep_optional_configuration_key48_require_present(
    const sep_optional_configuration_key48_t *value
) {
    if (!sep_optional_configuration_key48_is_present(value)) {
        sep_fatal_wait_loop();
    }
    return value;
}

void sep_optional_configuration_key48_initialize_from_data(
    sep_optional_configuration_key48_t *output,
    const void *data,
    sep_size_t length
) {
    if (output == 0 || length >= 49) {
        sep_fatal_wait_loop();
    }
    sep_memzero(output, sizeof(*output));
    sep_memmove_checked(output->bytes, data, length, sizeof(output->bytes));
    output->present = 1;
}

void sep_write_configuration_key_sink(
    const sep_optional_configuration_key48_t *material,
    sep_bool include_material,
    sep_u32 configuration_word
) {
    sep_u32 block[SEP_CONFIGURATION_KEY_SINK_WORDS];
    sep_memzero(block, sizeof(block));

    volatile sep_u32 *const control =
        open_secure_rom_configuration_sink_control();
    if ((*control & 1) != 0) {
        sep_fatal_wait_loop();
    }
    if (include_material &&
        sep_optional_configuration_key48_is_present(material)) {
        memcpy(block, material->bytes, sizeof(material->bytes));
        block[12] = configuration_word;
    }

    volatile sep_u32 *const sink =
        open_secure_rom_configuration_sink_words();
    for (sep_size_t index = 0;
         index < SEP_CONFIGURATION_KEY_SINK_WORDS;
         ++index) {
        sink[index] = block[index];
    }
    *control |= 1;
    if ((*control & 1) == 0) {
        sep_fatal_wait_loop();
    }
}

void sep_write_context_configuration_key_sink(
    const void *context,
    sep_bool include_material
) {
    if (context == 0 || ((uintptr_t)context & 7) != 0) {
        sep_fatal_wait_loop();
    }
    const sep_u8 *bytes = context;
    sep_optional_configuration_key48_t material;
    sep_u32 configuration_word;
    sep_memmove(&material, &bytes[0x6b], sizeof(material));
    sep_memmove(
        &configuration_word,
        &bytes[4],
        sizeof(configuration_word)
    );
    sep_write_configuration_key_sink(
        &material,
        include_material,
        configuration_word
    );
}
