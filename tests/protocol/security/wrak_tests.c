#include "open_secure_rom/wrak.h"

#include <assert.h>
#include <string.h>

static sep_u16 requested_record;
static sep_u32 derivation_begin_selector;
static sep_u32 derivation_end_selectors[2];
static sep_size_t derivation_end_count;

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected WRAK fatal path");
    __builtin_unreachable();
}

void __attribute__((noreturn)) sep_panic_with_reason_and_pc(
    sep_u32 reason,
    sep_u64 caller_pc
) {
    (void)reason;
    (void)caller_pc;
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_panic_reason_1a(void) {
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_panic_reason_2f(void) {
    sep_fatal_wait_loop();
}

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    return event_code;
}

int sep_platform_wrak_autk_stage_status(void) {
    return 0;
}

sep_u32 sep_platform_wrak_autk_slot_count(void) {
    return 0;
}

void sep_platform_autp_install_begin_noop(
    const sep_u8 material[28],
    sep_size_t material_length,
    sep_u64 slot_group,
    const char *label
) {
    (void)material;
    (void)material_length;
    (void)slot_group;
    (void)label;
}

void sep_platform_wrak_autk_install_begin_noop(
    const sep_u8 material[28],
    sep_size_t material_length,
    sep_u32 selector,
    const char *label
) {
    (void)material;
    (void)material_length;
    (void)selector;
    (void)label;
}

void sep_platform_wrak_autk_invalid_selector_noop(sep_u32 selector) {
    (void)selector;
}

void sep_platform_wrak_autk_valid_selector_noop(sep_u32 selector) {
    (void)selector;
}

void sep_platform_wrak_autk_post_install(void) {}

sep_u32 sep_platform_required_capability_mask_zero_stub(void) {
    return 0;
}

void sep_platform_key_service_finalize_noop(sep_u32 capability_mask) {
    (void)capability_mask;
}

void sep_platform_key_material_transform_noop(
    const char *label,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
) {
    assert(strcmp(label, "shib") == 0);
    assert(source_length == 24);
    assert(output_length == 32);
    const sep_u8 *bytes = source;
    for (sep_size_t index = 0; index < output_length; ++index) {
        ((sep_u8 *)output)[index] = (sep_u8)(bytes[index % source_length] ^ 0x5a);
    }
}

void sep_platform_wrak_autk_prepare_hkdf_info(
    void *info,
    sep_size_t info_length
) {
    assert(info_length == 104);
    ((sep_u8 *)info)[0] = 0xa5;
}

void sep_platform_wrak_autk_derivation_begin_noop(
    sep_u32 selector,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
) {
    assert(source_length == 32 && output_length == 32);
    derivation_begin_selector = selector;
    memcpy(output, source, output_length);
}

void sep_platform_wrak_autk_derivation_end_noop(
    sep_u32 selector,
    const void *source,
    sep_size_t source_length,
    void *output,
    sep_size_t output_length
) {
    assert(source_length == 32 && output_length == 32);
    assert(derivation_end_count < 2);
    derivation_end_selectors[derivation_end_count++] = selector;
    const sep_u8 *bytes = source;
    for (sep_size_t index = 0; index < output_length; ++index) {
        ((sep_u8 *)output)[index] = (sep_u8)(bytes[index] ^ (0x31 + selector));
    }
}

sep_bool sep_ake_find_authenticated_record(
    sep_u16 record_selector,
    sep_u8 *output
) {
    requested_record = record_selector;
    for (sep_size_t index = 0; index < 32; ++index) {
        output[index] = (sep_u8)(record_selector + index + 1);
    }
    return 1;
}

int sep_hkdf_by_bit_length(
    sep_size_t digest_bit_length,
    sep_size_t ikm_length,
    const void *ikm,
    sep_size_t salt_length,
    const void *salt,
    sep_size_t info_length,
    const void *info,
    sep_size_t derived_key_length,
    void *derived_key
) {
    assert(digest_bit_length == 384);
    assert(ikm_length == 32 && ikm != NULL);
    assert(salt_length == 0 && salt == NULL);
    assert(info_length == 104 && ((const sep_u8 *)info)[0] == 0xa5);
    assert(derived_key_length == 60);
    for (sep_size_t index = 0; index < derived_key_length; ++index) {
        ((sep_u8 *)derived_key)[index] = (sep_u8)(0x40 + index);
    }
    return 0;
}

void *sep_fill_research_seed_pattern(void *buffer, sep_size_t length) {
    static const sep_u8 pattern[4] = {0xef, 0xbe, 0xad, 0xde};
    sep_u8 *bytes = buffer;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = pattern[index & 3];
    }
    return buffer;
}

int main(void) {
    sep_u8 zero[28] = {0};
    assert(!sep_wrak_autk_buffer_has_nonzero_byte(zero, sizeof(zero)));
    zero[27] = 1;
    assert(sep_wrak_autk_buffer_has_nonzero_byte(zero, sizeof(zero)));
    sep_wrak_autk_install_autp_material(zero, 1);
    sep_wrak_autk_install_labeled_key_material(zero, 0, "wrak");
    sep_wrak_autk_install_labeled_key_material(zero, 2, "autk");
    sep_wrak_autk_apply_selector_to_provider(5, 0);
    sep_wrak_autk_commit_research_pattern();
    sep_wrak_autk_stage_research_pattern();

    sep_u8 *state = open_secure_rom_wrak_test_state();
    memset(state, 0, 0x60);
    sep_wrak_autk_import_type7_record();
    assert(requested_record == 7);
    assert(state[1] == 1);
    for (sep_size_t index = 0; index < 28; ++index) {
        assert(state[4 + index] == (sep_u8)(8 + index));
    }

    sep_wrak_autk_derive_and_install_from_type8_record();
    assert(requested_record == 8);
    assert(derivation_begin_selector == 0);
    assert(derivation_end_count == 2);
    assert(derivation_end_selectors[0] == 0);
    assert(derivation_end_selectors[1] == 2);
    assert(state[0] == 1 && state[2] == 1);
    assert(state[32] == 0x40 && state[33] == 0xb0);
    for (sep_size_t index = 0; index < 16; ++index) {
        assert(state[48 + index] != 0);
    }
    assert(sep_wrak_autk_read_result_word(0) == 0x0000b040);
}
