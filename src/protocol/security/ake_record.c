#include "open_secure_rom/ake.h"

#include "open_secure_rom/crypto_digest.h"
#include "open_secure_rom/crypto_hmac.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/provisioning.h"
#include "open_secure_rom/runtime.h"

static sep_u8 record_service_initialized;
static sep_u8 record_service_selected;
static sep_u8 record_service_closed;
static sep_u8 record_service_keys[64];
typedef struct ake_record_fixture {
    sep_u8 index;
    sep_u8 metadata[2];
    sep_u8 bytes[SEP_AKE_RECORD_SIZE];
} ake_record_fixture_t;

static ake_record_fixture_t record_fixtures[2];
static sep_u8 prepared_type9_table[144];
static sep_ake_transport_failure_record_t cached_failure_record;

static const sep_u8 record_service_kdf_context[24] = {
    0x03, 0x3b, 0x0a, 0xd1, 0x4f, 0x05, 0x21, 0x49,
    0x94, 0x42, 0xfd, 0x56, 0x9e, 0x9c, 0xa4, 0xa8,
    0xb9, 0xc6, 0x30, 0xa8, 0xa7, 0xff, 0x08, 0x04,
};

static void require(sep_bool condition) {
    if (!condition) {
        sep_fatal_wait_loop();
    }
}

static sep_bool supported_record_type(sep_u8 type) {
    return type >= 1 && type <= 25;
}

static void record_hmac(
    const sep_u8 *record,
    const sep_u8 *key,
    sep_u8 *authenticator,
    sep_bool contiguous
) {
    const sep_ccdigest_info_t *digest = sep_ccsha256_di();
    sep_cchmac_ctx_t context;
    sep_u8 full[32];
    sep_memzero(&context, sizeof(context));
    sep_cchmac_init(digest, &context, 32, key);
    if (contiguous) {
        sep_cchmac_update(digest, &context, 48, record);
    } else {
        sep_cchmac_update(digest, &context, 14, record);
        sep_cchmac_update(digest, &context, 2, record + 30);
        sep_cchmac_update(digest, &context, 32, record + 32);
    }
    sep_cchmac_final(digest, &context, full);
    sep_memmove(authenticator, full, 16);
    sep_memzero(full, sizeof(full));
}

static ake_record_fixture_t *find_fixture(sep_u8 record_index) {
    for (sep_size_t index = 0; index < sizeof(record_fixtures) / sizeof(record_fixtures[0]); ++index) {
        if (record_fixtures[index].index == record_index) {
            return &record_fixtures[index];
        }
    }
    return NULL;
}

void open_secure_rom_ake_record_service_load_record(
    sep_u8 record_index,
    const sep_u8 record[SEP_AKE_RECORD_SIZE]
) {
    require(record_index >= 1 && record_index <= SEP_AKE_RECORD_COUNT &&
        record != NULL);
    ake_record_fixture_t *fixture = find_fixture(record_index);
    if (fixture == NULL) {
        for (sep_size_t index = 0; index < sizeof(record_fixtures) / sizeof(record_fixtures[0]); ++index) {
            if (record_fixtures[index].index == 0) {
                fixture = &record_fixtures[index];
                fixture->index = record_index;
                break;
            }
        }
    }
    require(fixture != NULL);
    sep_memmove(fixture->bytes, record, SEP_AKE_RECORD_SIZE);
    fixture->metadata[0] = 0;
    fixture->metadata[1] = 0;
}

void sep_ake_cache_transport_failure_record_if_reserved_zero(
    const void *site_tag,
    const sep_ake_transport_failure_record_t *record
) {
    (void)site_tag;
    require(record != NULL);
    for (sep_size_t index = 40; index < 47; ++index) {
        if (record->bytes[index] != 0) {
            return;
        }
    }
    cached_failure_record = *record;
}

sep_ake_transport_failure_record_t
sep_ake_get_cached_transport_failure_record(void) {
    return cached_failure_record;
}

void sep_ake_normalize_record_service_key_source(
    sep_u8 output[32],
    sep_size_t output_size,
    const void *source,
    sep_size_t source_size
) {
    require(output != NULL && output_size == 32 && source != NULL &&
        source_size < 25);
    sep_u8 padded_source[24];
    sep_memzero(padded_source, sizeof(padded_source));
    sep_memmove(padded_source, source, source_size);
    require(sep_ake_buffer_has_nonzero_byte(padded_source,
        sizeof(padded_source)));
    sep_ccdigest(
        sep_ccsha256_di(),
        sizeof(padded_source),
        padded_source,
        output
    );
    require(sep_ake_buffer_has_nonzero_byte(output, 32));
    sep_memzero(padded_source, sizeof(padded_source));
}

void sep_ake_derive_record_service_keys(
    sep_u8 *sp_key,
    sep_size_t sp_key_size,
    sep_u8 *counter_block_mac_key,
    sep_size_t counter_block_mac_key_size,
    const void *source,
    sep_size_t source_size
) {
    require(sp_key != NULL && sp_key_size == 32 &&
        counter_block_mac_key != NULL && counter_block_mac_key_size == 32);
    sep_u8 normalized[32];
    static const sep_u8 sp_label[6] = {'S', 'P', ' ', 'k', 'e', 'y'};
    static const sep_u8 counter_label[21] = {
        'C', 'o', 'u', 'n', 't', 'e', 'r', ' ', 'b', 'l', 'o', 'c', 'k',
        ' ', 'M', 'A', 'C', ' ', 'k', 'e', 'y'
    };
    sep_ake_normalize_record_service_key_source(
        normalized,
        sizeof(normalized),
        source,
        source_size
    );
    require(sep_cchkdf(sep_ccsha256_di(), 32, normalized, 0, NULL,
        sizeof(sp_label), sp_label, 32, sp_key) == 0);
    require(sep_cchkdf(sep_ccsha256_di(), 32, normalized, 0, NULL,
        sizeof(counter_label), counter_label, 32,
        counter_block_mac_key) == 0);
    sep_memzero(normalized, sizeof(normalized));
}

void sep_ake_initialize_record_service_keys(void) {
    sep_ake_derive_record_service_keys(
        record_service_keys,
        32,
        record_service_keys + 32,
        32,
        record_service_kdf_context,
        sizeof(record_service_kdf_context)
    );
    record_service_initialized = 1;
}

sep_bool sep_ake_select_record(sep_u8 record_index) {
    require(record_service_closed != 1 && record_index >= 1 &&
        record_index <= SEP_AKE_RECORD_COUNT);
    if (!record_service_initialized) {
        sep_ake_initialize_record_service_keys();
    }
    record_service_selected = record_index;
    return find_fixture(record_index) != NULL;
}

void sep_ake_cache_record_metadata(sep_u8 record_index) {
    require(record_service_closed != 1 && record_index >= 1 &&
        record_index <= SEP_AKE_RECORD_COUNT && record_service_selected != 0);
    ake_record_fixture_t *fixture = find_fixture(record_index);
    if (fixture == NULL || !sep_ake_verify_record_crc16(fixture->bytes)) {
        return;
    }
    fixture->metadata[0] = fixture->bytes[4];
    fixture->metadata[1] = fixture->bytes[4] == 9
        ? fixture->bytes[10]
        : 0;
}

sep_bool sep_ake_find_authenticated_record(
    sep_u16 record_selector,
    sep_u8 *output
) {
    require(output != NULL && record_service_closed != 1);
    if (!record_service_initialized) {
        sep_ake_initialize_record_service_keys();
    }
    const sep_u8 type = (sep_u8)record_selector;
    const sep_u8 subtype = (sep_u8)(record_selector >> 8);
    for (sep_size_t fixture_index = 0; fixture_index < sizeof(record_fixtures) / sizeof(record_fixtures[0]);
        ++fixture_index) {
        ake_record_fixture_t *fixture = &record_fixtures[fixture_index];
        if (fixture->index == 0) {
            continue;
        }
        if (fixture->metadata[0] == 0) {
            sep_ake_select_record(fixture->index);
            sep_ake_cache_record_metadata(fixture->index);
        }
        if (fixture->metadata[0] != type ||
            (type == 9 && fixture->metadata[1] != subtype)) {
            continue;
        }
        if (sep_ake_verify_record_authenticator(fixture->bytes,
            record_service_keys + 32, 32)) {
            sep_memmove(output, fixture->bytes + 32, 32);
            return 1;
        }
    }
    return 0;
}

void sep_ake_close_record_service(void) {
    record_service_selected = 0;
    record_service_closed = 1;
}

sep_bool sep_ake_record_service_is_closed(void) {
    return record_service_closed;
}

sep_bool sep_ake_verify_record_crc16(const sep_u8 *record) {
    if (record == NULL) {
        sep_ake_verify_record_crc16_null_assert();
    }
    const sep_u8 type = record[4];
    const sep_size_t length = type >= 3 && type <= 25 ? 14 : 30;
    const sep_u16 expected = (sep_u16)record[30] |
        ((sep_u16)record[31] << 8);
    return sep_crc16_update(record, length, 0xffff) == expected;
}

void __attribute__((noreturn)) sep_ake_verify_record_crc16_null_assert(void) {
    sep_fatal_wait_loop();
}

void sep_ake_compute_record_types_1_2_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
) {
    require(record != NULL && authentication_key != NULL &&
        authenticator != NULL && record[4] >= 1 && record[4] <= 2);
    record_hmac(record, authentication_key, authenticator, 1);
}

void sep_ake_compute_record_type_3_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
) {
    require(record != NULL && authentication_key != NULL &&
        authenticator != NULL && record[4] == 3);
    record_hmac(record, authentication_key, authenticator, 0);
}

void sep_ake_compute_record_types_4_6_and_10_25_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
) {
    const sep_u8 type = record != NULL ? record[4] : 0;
    require(authentication_key != NULL && authenticator != NULL &&
        ((type >= 4 && type <= 6) || (type >= 10 && type <= 25)));
    record_hmac(record, authentication_key, authenticator, 0);
}

void sep_ake_compute_record_types_7_8_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
) {
    require(record != NULL && authentication_key != NULL &&
        authenticator != NULL && record[4] >= 7 && record[4] <= 8);
    record_hmac(record, authentication_key, authenticator, 0);
}

void sep_ake_compute_record_type_9_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
) {
    require(record != NULL && authentication_key != NULL &&
        authenticator != NULL && record[4] == 9);
    record_hmac(record, authentication_key, authenticator, 0);
}

sep_bool sep_ake_verify_record_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_size_t authentication_key_size
) {
    require(record != NULL && authentication_key != NULL &&
        authentication_key_size == 32);
    if (!sep_ake_verify_record_crc16(record) ||
        !supported_record_type(record[4])) {
        return 0;
    }
    sep_u8 computed[16];
    const sep_u8 *expected = record + 14;
    if (record[4] <= 2) {
        sep_ake_compute_record_types_1_2_authenticator(
            record,
            authentication_key,
            computed
        );
        expected = record + 48;
    } else if (record[4] == 3) {
        sep_ake_compute_record_type_3_authenticator(
            record,
            authentication_key,
            computed
        );
    } else if ((record[4] >= 4 && record[4] <= 6) || record[4] >= 10) {
        sep_ake_compute_record_types_4_6_and_10_25_authenticator(
            record,
            authentication_key,
            computed
        );
    } else if (record[4] <= 8) {
        sep_ake_compute_record_types_7_8_authenticator(
            record,
            authentication_key,
            computed
        );
    } else {
        sep_ake_compute_record_type_9_authenticator(
            record,
            authentication_key,
            computed
        );
    }
    const sep_bool matches = sep_constant_time_memcmp(computed, expected, 16)
        == 0;
    sep_memzero(computed, sizeof(computed));
    return matches;
}

sep_bool sep_ake_prepare_type9_record_table(sep_u8 subtype) {
    sep_u8 payload[32];
    sep_memzero(payload, sizeof(payload));
    if (!sep_ake_find_authenticated_record((sep_u16)(9 | (subtype << 8)),
        payload)) {
        return 0;
    }
    sep_optional_configuration_key48_t key =
        sep_optional_configuration_key48_from_sha384(payload, 16);
    sep_memmove(prepared_type9_table, key.bytes, 48);
    key = sep_optional_configuration_key48_from_sha384(payload + 16, 16);
    sep_memmove(prepared_type9_table + 48, key.bytes, 48);
    key = sep_optional_configuration_key48_from_sha384(payload, 32);
    sep_memmove(prepared_type9_table + 96, key.bytes, 48);
    sep_memzero(payload, sizeof(payload));
    return 1;
}

sep_u32 sep_ake_read_prepared_table_word(sep_size_t byte_offset) {
    require(byte_offset < 141);
    return (sep_u32)prepared_type9_table[byte_offset] |
        ((sep_u32)prepared_type9_table[byte_offset + 1] << 8) |
        ((sep_u32)prepared_type9_table[byte_offset + 2] << 16) |
        ((sep_u32)prepared_type9_table[byte_offset + 3] << 24);
}
