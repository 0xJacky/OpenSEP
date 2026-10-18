#include "open_secure_rom/mailbox.h"
#include "open_secure_rom/protocol.h"
#include "open_secure_rom/runtime.h"

static sep_optional_research_seed_t research_seed;
static sep_u64 research_value64;
static sep_u8 research_pattern[32];
static sep_size_t research_pattern_offset;
static sep_u32 command11_word;
static sep_u32 protocol_phase;

void open_secure_rom_protocol_phase_reset(void) {
    protocol_phase = 0;
}

sep_u32 open_secure_rom_protocol_phase(void) {
    return protocol_phase;
}

void *sep_fill_research_seed_pattern(void *buffer, sep_size_t length) {
    static const sep_u8 pattern[4] = {0xef, 0xbe, 0xad, 0xde};
    sep_u8 *bytes = buffer;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = pattern[index & 3];
    }
    return buffer;
}

sep_bool sep_research_seed_is_initialized(void) {
    return sep_buffer_has_nonzero_byte(research_seed.bytes, sizeof(research_seed.bytes));
}

sep_bool sep_initialize_research_seed(void) {
    if (sep_research_seed_is_initialized()) {
        sep_fatal_wait_loop();
    }
    sep_fill_research_seed_pattern(research_seed.bytes, sizeof(research_seed.bytes));
    research_seed.present = 1;
    if (!sep_research_seed_is_initialized()) {
        sep_fatal_wait_loop();
    }
    return 1;
}

void sep_clear_research_seed(void) {
    sep_memzero(&research_seed, sizeof(research_seed));
}

sep_optional_research_seed_t sep_get_optional_research_seed(void) {
    return research_seed;
}

sep_bool sep_optional_research_seed_is_present(
    const sep_optional_research_seed_t *value
) {
    if (value->present > 1) {
        sep_fatal_wait_loop();
    }
    return value->present;
}

const sep_optional_research_seed_t *sep_optional_research_seed_require_present(
    const sep_optional_research_seed_t *value
) {
    if (!sep_optional_research_seed_is_present(value)) {
        sep_fatal_wait_loop();
    }
    return value;
}

void sep_clear_research_value64(void) {
    research_value64 = 0;
}

sep_bool sep_research_value64_is_initialized(void) {
    return sep_buffer_has_nonzero_byte(&research_value64, sizeof(research_value64));
}

sep_bool sep_initialize_research_value64(void) {
    if (sep_research_value64_is_initialized()) {
        sep_fatal_wait_loop();
    }
    sep_fill_research_seed_pattern(&research_value64, sizeof(research_value64));
    if (!sep_research_value64_is_initialized()) {
        sep_fatal_wait_loop();
    }
    return 1;
}

void sep_optional_research_value64_initialize_from_bytes(
    sep_optional_research_value64_t *result,
    const void *bytes,
    sep_size_t length
) {
    if (length > sizeof(result->value)) {
        sep_fatal_wait_loop();
    }
    result->value = 0;
    sep_memmove(&result->value, bytes, length);
    result->present = 1;
}

sep_optional_research_value64_t sep_optional_research_value64_from_bytes(
    const void *bytes,
    sep_size_t length
) {
    if (length != sizeof(sep_u64)) {
        sep_fatal_wait_loop();
    }
    sep_optional_research_value64_t result;
    sep_optional_research_value64_initialize_from_bytes(&result, bytes, length);
    return result;
}

sep_optional_research_value64_t sep_get_optional_research_value64(void) {
    if (!sep_research_value64_is_initialized()) {
        return (sep_optional_research_value64_t){.value = 0, .present = 0};
    }
    return sep_optional_research_value64_from_bytes(
        &research_value64,
        sizeof(research_value64)
    );
}

sep_bool sep_optional_research_value64_is_present(
    const sep_optional_research_value64_t *value
) {
    if (value->present > 1) {
        sep_fatal_wait_loop();
    }
    return value->present;
}

const sep_optional_research_value64_t *
sep_optional_research_value64_require_present(
    const sep_optional_research_value64_t *value
) {
    if (!sep_optional_research_value64_is_present(value)) {
        sep_fatal_wait_loop();
    }
    return value;
}

void sep_require_initialized_research_value64(void) {
    const sep_optional_research_value64_t value =
        sep_get_optional_research_value64();
    sep_optional_research_value64_require_present(&value);
}

sep_u32 sep_mailbox_get_command11_word(void) {
    return command11_word;
}

sep_mailbox_slot_t sep_protocol_build_response(
    sep_u8 sequence,
    sep_u8 tag,
    sep_u8 argument,
    sep_u32 payload
) {
    return (sep_mailbox_slot_t){
        .low = 0xffULL |
            ((sep_u64)sequence << 8) |
            ((sep_u64)tag << 16) |
            ((sep_u64)argument << 24) |
            ((sep_u64)payload << 32),
        .high = 0,
    };
}

static sep_u32 load_le32(const sep_u8 *bytes) {
    return (sep_u32)bytes[0] |
        ((sep_u32)bytes[1] << 8) |
        ((sep_u32)bytes[2] << 16) |
        ((sep_u32)bytes[3] << 24);
}

sep_protocol_dispatch_result_t sep_protocol_dispatch_request(sep_u64 request) {
    const sep_u8 frame_tag = (sep_u8)request;
    const sep_u8 sequence = (sep_u8)(request >> 8);
    const sep_u8 opcode = (sep_u8)(request >> 16);
    const sep_u8 argument = (sep_u8)(request >> 24);
    sep_u8 response_tag = (sep_u8)(opcode + 0x64);
    sep_u8 response_argument = 0;
    sep_u32 payload = 0;
    sep_u32 result_phase = 0;

    if (frame_tag != 0xff) {
        sep_protocol_dispatch_result_t result;
        result.response = (sep_mailbox_slot_t){
            .low = request & 0xff,
            .high = 0,
        };
        result.has_response = 1;
        result.phase = 0;
        result.shared_region_base = 0;
        result.shared_region_mode = 0;
        return result;
    }

    switch (opcode) {
    case SEP_MAILBOX_REQUEST_QUERY_CAPABILITY:
        break;
    case SEP_MAILBOX_REQUEST_QUERY_PHASE:
        payload = protocol_phase == 0 ? 1 : 2;
        break;
    case SEP_MAILBOX_REQUEST_INITIALIZE_RESEARCH_SEED:
        if (!sep_research_seed_is_initialized()) {
            sep_initialize_research_seed();
        }
        payload = 160;
        break;
    case SEP_MAILBOX_REQUEST_READ_RESEARCH_SEED_WORD: {
        const sep_optional_research_seed_t value =
            sep_get_optional_research_seed();
        if (argument > 4) {
            response_argument = 0xff;
            payload = UINT32_MAX;
            break;
        }
        const sep_optional_research_seed_t *present =
            sep_optional_research_seed_require_present(&value);
        const sep_size_t offset = (sep_size_t)argument * sizeof(sep_u32);
        payload = load_le32(&present->bytes[offset]);
        response_argument = argument;
        break;
    }
    case SEP_MAILBOX_REQUEST_PUBLISH_AKE_READY:
        if (protocol_phase != 0) {
            response_tag = 0xc7;
            payload = opcode;
            break;
        }
        response_tag = 0x69;
        protocol_phase = 1;
        result_phase = 1;
        break;
    case SEP_MAILBOX_REQUEST_PUBLISH_SHARED_REGION:
        if (protocol_phase == 0) {
            response_tag = 0xc7;
            payload = opcode;
            break;
        }
        if (argument > 1) {
            sep_fatal_wait_loop();
        }
        protocol_phase = 2;
        return (sep_protocol_dispatch_result_t){
            .response = {0, 0},
            .has_response = 0,
            .phase = 2,
            .shared_region_base = (request >> 32) << 12,
            .shared_region_mode = argument,
        };
    case SEP_MAILBOX_REQUEST_STREAM_RESEARCH_PATTERN: {
        if (research_pattern_offset >= sizeof(research_pattern)) {
            research_pattern_offset = 0;
        }
        if (research_pattern_offset == 0) {
            sep_fill_research_seed_pattern(
                research_pattern,
                sizeof(research_pattern)
            );
        }
        const sep_size_t offset = research_pattern_offset;
        payload = load_le32(&research_pattern[offset]);
        research_pattern_offset += sizeof(sep_u32);
        break;
    }
    case SEP_MAILBOX_REQUEST_SET_COMMAND11_WORD:
        if (protocol_phase != 0) {
            response_tag = 0xc7;
            payload = opcode;
            break;
        }
        command11_word = (sep_u32)(request >> 32);
        break;
    case SEP_MAILBOX_REQUEST_INITIALIZE_RESEARCH_VALUE64:
        if (!sep_research_value64_is_initialized()) {
            sep_initialize_research_value64();
            sep_require_initialized_research_value64();
        }
        payload = 64;
        break;
    case SEP_MAILBOX_REQUEST_READ_RESEARCH_VALUE64_WORD: {
        const sep_optional_research_value64_t value =
            sep_get_optional_research_value64();
        const sep_optional_research_value64_t *present =
            sep_optional_research_value64_require_present(&value);
        if (argument > 1) {
            response_argument = 0xff;
            payload = UINT32_MAX;
        } else {
            response_argument = argument;
            payload = argument == 0
                ? (sep_u32)present->value
                : (sep_u32)(present->value >> 32);
        }
        break;
    }
    default:
        response_tag = 0xc7;
        payload = opcode;
        break;
    }

    sep_protocol_dispatch_result_t result;
    result.response = sep_protocol_build_response(
        sequence,
        response_tag,
        response_argument,
        payload
    );
    result.has_response = 1;
    result.phase = result_phase;
    result.shared_region_base = 0;
    result.shared_region_mode = 0;
    return result;
}
