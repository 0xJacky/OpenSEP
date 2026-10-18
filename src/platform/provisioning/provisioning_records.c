#include "open_secure_rom/system_closure.h"

#include "open_secure_rom/configuration_sink.h"
#include "open_secure_rom/crypto_hmac.h"
#include "open_secure_rom/event_log.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/provisioning.h"
#include "open_secure_rom/runtime.h"

enum {
    PROVISIONING_RECORDS_OFFSET = 24,
    PROVISIONING_AUTHENTICATION_KEY_OFFSET = 89,
    PROVISIONING_OPTIONAL_KEY_OFFSET = 121,
    PROVISIONING_OPTIONAL_SEED_OFFSET = 170,
    PROVISIONING_SCRATCH_OFFSET = 191,
};

static sep_u32 record_event(
    sep_size_t record_index,
    sep_u32 event_code
) {
    if ((record_index >> 32) != 0) {
        sep_panic_reason_2a();
    }
    return sep_platform_provisioning_record_index_event_bits(record_index) |
        event_code;
}

sep_bool sep_platform_provisioning_install_artm_authentication_key(
    sep_platform_provisioning_state_t *state,
    sep_size_t record_index
) {
    if (state == NULL || ((uintptr_t)state & 7) != 0) {
        sep_panic_reason_1a();
    }
    const sep_u64 record = sep_platform_provisioning_record_word_at(
        (const sep_u64 *)(const void *)&state->bytes[PROVISIONING_RECORDS_OFFSET],
        record_index
    );
    if ((record & 0x00ff0000000000ULL) != 0x00200000000000ULL) {
        sep_protocol_event_log_append(
            record_event(record_index, 0x40090005)
        );
        return 0;
    }
    if (!sep_platform_provisioning_record_crc16_is_valid(
            state,
            record_index
        )) {
        sep_protocol_event_log_append(
            record_event(record_index, 0x40090006)
        );
        return 0;
    }
    if (!open_secure_rom_provisioning_install_artm_from_payload(
            state,
            &state->bytes[PROVISIONING_SCRATCH_OFFSET]
        )) {
        sep_protocol_event_log_append(0x40080001);
        return 0;
    }
    return 1;
}

sep_bool sep_platform_provisioning_extract_research_values(
    sep_platform_provisioning_state_t *state,
    sep_size_t record_index
) {
    if (state == NULL || ((uintptr_t)state & 7) != 0) {
        sep_panic_reason_1a();
    }
    const sep_u64 record = sep_platform_provisioning_record_word_at(
        (const sep_u64 *)(const void *)&state->bytes[PROVISIONING_RECORDS_OFFSET],
        record_index
    );
    if ((record & 0x00ff0000000000ULL) != 0x00560000000000ULL) {
        sep_protocol_event_log_append(
            record_event(record_index, 0x40090007)
        );
        return 0;
    }
    if (!sep_platform_provisioning_record_crc16_is_valid(
            state,
            record_index
        )) {
        sep_protocol_event_log_append(
            record_event(record_index, 0x4009000a)
        );
        return 0;
    }

    const sep_u8 *payload = &state->bytes[PROVISIONING_SCRATCH_OFFSET];
    sep_u8 message[71];
    message[0] = 2;
    sep_memmove(message + 1, payload, 70);
    if (!sep_hmac_sha256_tag_matches(
            &state->bytes[PROVISIONING_AUTHENTICATION_KEY_OFFSET],
            message,
            sizeof(message),
            payload + 70,
            16
        )) {
        sep_protocol_event_log_append(0x40080003);
        return 0;
    }

    sep_optional_configuration_key48_t key;
    sep_optional_research_seed_t seed;
    sep_memzero(&key, sizeof(key));
    sep_memzero(&seed, sizeof(seed));
    sep_size_t offset = 0;
    if (payload[offset] != 0) {
        if (payload[offset] != 1) {
            sep_protocol_event_log_append(
                record_event(record_index, 0x40090008)
            );
            return 0;
        }
        sep_optional_configuration_key48_initialize_from_data(
            &key,
            payload + offset + 1,
            48
        );
        offset = 49;
    }
    if (payload[offset] != 0) {
        if (payload[offset] != 1) {
            sep_protocol_event_log_append(
                record_event(record_index, 0x40090009)
            );
            return 0;
        }
        sep_optional_research_seed_initialize_from_data(
            &seed,
            payload + offset + 1,
            20
        );
    }
    sep_memmove(
        &state->bytes[PROVISIONING_OPTIONAL_KEY_OFFSET],
        &key,
        sizeof(key)
    );
    sep_memmove(
        &state->bytes[PROVISIONING_OPTIONAL_SEED_OFFSET],
        &seed,
        sizeof(seed)
    );
    return 1;
}
