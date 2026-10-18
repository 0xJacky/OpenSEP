#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/shared_image.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    return event_code;
}

int main(void) {
    sep_shared_image_context_t context = {0};
    sep_shared_image_context_set_mode(&context, 4);
    sep_shared_image_context_set_payload_type(&context, 0x73657072);
    assert(sep_shared_image_context_mode_checked(&context) == 4);
    assert(sep_shared_image_context_payload_type_checked(&context) ==
        0x73657072);

    sep_shared_image_properties_t properties;
    sep_shared_image_properties_initialize(&properties);
    assert(properties.bytes[0] == 2);
    assert(properties.bytes[106] == 0);
    assert(properties.bytes[242] == 0);

    sep_shared_image_properties_set_chip(&properties, 0xfe01);
    assert(properties.bytes[10] == 1);
    assert(properties.bytes[12] == 0x01);
    assert(properties.bytes[13] == 0xfe);
    sep_shared_image_properties_set_ecid(
        &properties,
        0x0123456789abcdefULL
    );
    assert(properties.bytes[16] == 1);

    sep_u8 digest_data[48] = {0};
    digest_data[47] = 0xa5;
    const sep_checked_bytes48_t digest =
        sep_checked_bytes48_from_data(digest_data, sizeof(digest_data));
    sep_shared_image_properties_set_dgst(&properties, &digest);
    assert(sep_shared_image_properties_has_dgst(&properties) == 1);
    assert(sep_shared_image_properties_dgst_matches_if_present(
        &properties,
        &digest
    ) == 1);

    sep_shared_image_properties_set_ekey(&properties, 1);
    sep_shared_image_properties_set_eg0t(&properties, 1);
    sep_shared_image_properties_mark_amnm(&properties);
    sep_shared_image_properties_mark_dsec(&properties);
    assert(sep_shared_image_properties_ekey_checked(&properties) == 1);
    assert(sep_shared_image_properties_eg0t_checked(&properties) == 1);
    assert(sep_shared_image_properties_amnm_checked(&properties) == 1);
    assert(sep_shared_image_properties_dsec_checked(&properties) == 1);

    sep_shared_image_auxiliary_t auxiliary;
    sep_shared_image_auxiliary_initialize(&auxiliary);
    assert(auxiliary.present == 0);
    sep_shared_image_auxiliary_keybag_entry_t *entry =
        sep_shared_image_auxiliary_keybag_entry_at(&auxiliary, 2);
    entry->present = 1;
    entry->key_bit_length = 256;
    assert(auxiliary.entries[2].key_bit_length == 256);
    sep_shared_image_payload_keybag_initialize_absent(entry);
    assert(entry->present == 0);
    assert(entry->key_bit_length == 0);

    const sep_optional_u8_t absent = sep_optional_u8_initialize_absent();
    assert(absent.present == 1);
    assert(absent.value == 0);
}
