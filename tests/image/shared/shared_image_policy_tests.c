#include "open_secure_rom/platform.h"
#include "open_secure_rom/protocol.h"
#include "open_secure_rom/shared_image.h"

#include <assert.h>

static sep_optional_research_seed_t current_seed;

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    return event_code;
}

void sep_protocol_log_diagnostic_payload(
    sep_u32 event_code,
    const void *payload,
    sep_size_t payload_length
) {
    (void)event_code;
    (void)payload;
    (void)payload_length;
}

sep_u32 sep_platform_read_flag_08_boolean_encoded(void) {
    return 1;
}

sep_u32 sep_platform_read_flag_0c_boolean_encoded(void) {
    return 1;
}

sep_u32 sep_platform_zero_result_stub(void) {
    return 0;
}

sep_optional_research_seed_t sep_get_optional_research_seed(void) {
    return current_seed;
}

sep_bool sep_optional_research_seed_is_present(
    const sep_optional_research_seed_t *value
) {
    return value->present;
}

const sep_optional_research_seed_t *sep_optional_research_seed_require_present(
    const sep_optional_research_seed_t *value
) {
    assert(value->present == 1);
    return value;
}

sep_bool sep_checked_bytes20_equal(
    const sep_checked_bytes20_t *left,
    const sep_checked_bytes20_t *right
) {
    if (left->initialized != 1 || right->initialized != 1) {
        return 0;
    }
    for (sep_size_t index = 0; index < 20; ++index) {
        if (left->bytes[index] != right->bytes[index]) {
            return 0;
        }
    }
    return 1;
}

sep_u8 sep_shared_image_context_mode_checked(
    const sep_shared_image_context_t *context
) {
    assert(context->decoded_properties[0] != 2);
    return context->decoded_properties[0];
}

int main(void) {
    sep_shared_image_context_t context = {0};
    context.decoded_properties[0] = 0;
    context.decoded_properties[56] = 1;
    assert(sep_shared_image_evaluate_research_policy(&context) == 1);

    context.decoded_properties[0] = 1;
    context.decoded_properties[206] = 1;
    for (sep_size_t index = 0; index < 20; ++index) {
        context.decoded_properties[207 + index] = (sep_u8)index;
        current_seed.bytes[index] = (sep_u8)index;
    }
    context.decoded_properties[227] = 1;
    current_seed.present = 1;
    assert(sep_shared_image_evaluate_research_policy(&context) == 1);

    current_seed.present = 0;
    assert(sep_shared_image_evaluate_research_policy(&context) == 6);
}
