#include "open_secure_rom/optional_values.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/runtime.h"

sep_optional_u8_t sep_optional_u8_initialize_absent(void) {
    const sep_u32 value = 0;
    sep_optional_u8_t output = {0, 0};
    sep_optional_u8_initialize_from_u32(&output, &value);
    return output;
}

void sep_optional_u8_initialize_from_u32(
    sep_optional_u8_t *output,
    const sep_u32 *value
) {
    if (output == 0 || *value >= 0x100) {
        sep_fatal_wait_loop();
    }
    output->present = 1;
    output->value = (sep_u8)*value;
}

void sep_optional_u8_initialize_from_u64(
    sep_optional_u8_t *output,
    const sep_u64 *value
) {
    if (output == 0 || *value >= 0x100) {
        sep_fatal_wait_loop();
    }
    output->present = 1;
    output->value = (sep_u8)*value;
}

void sep_optional_u16_initialize_absent(sep_optional_u16_t *value) {
    sep_optional_u16_initialize_absent_fields(value);
}

void sep_optional_u16_initialize_absent_fields(sep_optional_u16_t *value) {
    if (value == 0 || ((uintptr_t)value & 1) != 0) {
        sep_fatal_wait_loop();
    }
    value->present = 0;
    value->value = 0;
}

void sep_optional_u16_initialize_from_u64(
    sep_optional_u16_t *output,
    const sep_u64 *value
) {
    if (output == 0 || ((uintptr_t)output & 1) != 0 || *value >= 0x10000) {
        sep_fatal_wait_loop();
    }
    output->present = 1;
    output->value = (sep_u16)*value;
}

void sep_optional_u64_initialize_absent(sep_optional_u64_t *value) {
    sep_optional_u64_initialize_absent_fields(value);
}

void sep_optional_u64_initialize_absent_fields(sep_optional_u64_t *value) {
    if (value == 0 || ((uintptr_t)value & 7) != 0) {
        sep_fatal_wait_loop();
    }
    value->present = 0;
    value->value = 0;
}

void sep_optional_u64_initialize_from_u64(
    sep_optional_u64_t *output,
    const sep_u64 *value
) {
    if (output == 0 || ((uintptr_t)output & 7) != 0) {
        sep_fatal_wait_loop();
    }
    output->present = 1;
    output->value = *value;
}

void sep_optional_bool_initialize_from_bool(
    sep_optional_bool_t *output,
    const sep_bool *value
) {
    if (output == 0 || *value >= 2) {
        sep_fatal_wait_loop();
    }
    output->present = 1;
    output->value = *value;
}

sep_checked_bytes20_t sep_checked_bytes20_from_data(
    const sep_u8 *data,
    sep_size_t length
) {
    if (length != 20) {
        sep_fatal_wait_loop();
    }
    sep_checked_bytes20_t result;
    sep_memmove(result.bytes, data, sizeof(result.bytes));
    result.initialized = 1;
    return result;
}

sep_checked_bytes48_t sep_checked_bytes48_from_data(
    const sep_u8 *data,
    sep_size_t length
) {
    if (length != 48) {
        sep_fatal_wait_loop();
    }
    sep_checked_bytes48_t result;
    sep_memmove(result.bytes, data, sizeof(result.bytes));
    result.initialized = 1;
    return result;
}

int sep_checked_bytes48_compare(
    const sep_checked_bytes48_t *left,
    const sep_checked_bytes48_t *right
) {
    if (left->initialized != 1 || right->initialized != 1) {
        sep_fatal_wait_loop();
    }
    return sep_constant_time_memcmp_veneer(
        left->bytes,
        right->bytes,
        sizeof(left->bytes)
    );
}

sep_bool sep_checked_bytes48_equal(
    const sep_checked_bytes48_t *left,
    const sep_checked_bytes48_t *right
) {
    return sep_checked_bytes48_compare(left, right) == 0;
}

sep_bool sep_optional_u8_matches_or_log(
    sep_u16 expected,
    sep_u16 actual,
    sep_u32 missing_event,
    sep_u32 mismatch_event
) {
    const sep_u8 expected_present = (sep_u8)expected;
    const sep_u8 actual_present = (sep_u8)actual;
    if (expected_present >= 2 || actual_present >= 2) {
        sep_fatal_wait_loop();
    }
    if (expected_present == 0) {
        return 1;
    }
    if (actual_present == 0) {
        sep_protocol_event_log_append(missing_event);
        return 0;
    }
    if ((expected >> 8) == (actual >> 8)) {
        return 1;
    }
    sep_protocol_event_log_append(mismatch_event);
    return 0;
}

sep_bool sep_optional_bool_matches_or_log(
    sep_u16 expected,
    sep_u16 actual,
    sep_u32 missing_event,
    sep_u32 mismatch_event
) {
    const sep_u8 expected_present = (sep_u8)expected;
    const sep_u8 actual_present = (sep_u8)actual;
    if (expected_present >= 2 || actual_present >= 2 ||
        (expected >> 8) >= 2 || (actual >> 8) >= 2) {
        sep_fatal_wait_loop();
    }
    return sep_optional_u8_matches_or_log(expected, actual, missing_event, mismatch_event);
}

void sep_optional_research_seed_initialize_from_data(
    sep_optional_research_seed_t *output,
    const void *data,
    sep_size_t length
) {
    if (output == 0 || length > sizeof(output->bytes)) {
        sep_fatal_wait_loop();
    }
    sep_memzero(output->bytes, sizeof(output->bytes));
    sep_memmove_checked(
        output->bytes,
        data,
        length,
        sizeof(output->bytes)
    );
    output->present = 1;
}

sep_bool sep_checked_bytes32_any_nonzero(const sep_u8 bytes[32]) {
    if (bytes == 0) {
        sep_fatal_wait_loop();
    }
    return sep_buffer_has_nonzero_byte(bytes, 32);
}

int sep_checked_bytes32_compare_prefix(
    const sep_checked_bytes32_t *left,
    const sep_checked_bytes32_t *right,
    sep_size_t length
) {
    if (left->initialized != 1 || right->initialized != 1 || length > 32) {
        sep_fatal_wait_loop();
    }
    return sep_constant_time_memcmp_veneer(left, right, length);
}

sep_checked_bytes32_t *sep_checked_bytes32_initialize(
    sep_checked_bytes32_t *output,
    const void *data,
    sep_size_t length
) {
    if (output == 0 || length > sizeof(output->bytes)) {
        sep_fatal_wait_loop();
    }
    sep_memzero(output->bytes, sizeof(output->bytes));
    sep_memmove_checked(
        output->bytes,
        data,
        length,
        sizeof(output->bytes)
    );
    output->initialized = 1;
    return output;
}

sep_checked_bytes32_t sep_checked_bytes32_from_data(
    const void *data,
    sep_size_t length
) {
    sep_checked_bytes32_t result;
    sep_checked_bytes32_initialize(&result, data, length);
    return result;
}
