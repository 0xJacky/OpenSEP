#include "open_secure_rom/ake.h"

#include "open_secure_rom/provisioning.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    abort();
}

static const unsigned char service_context[24] = {
    0x03, 0x3b, 0x0a, 0xd1, 0x4f, 0x05, 0x21, 0x49,
    0x94, 0x42, 0xfd, 0x56, 0x9e, 0x9c, 0xa4, 0xa8,
    0xb9, 0xc6, 0x30, 0xa8, 0xa7, 0xff, 0x08, 0x04,
};

static void store_crc(unsigned char record[64]) {
    const unsigned char type = record[4];
    const size_t length = type >= 3 ? 14 : 30;
    const unsigned short crc = sep_crc16_update(record, length, 0xffff);
    record[30] = (unsigned char)crc;
    record[31] = (unsigned char)(crc >> 8);
}

static void test_context_layout_and_state(void) {
    sep_ake_context_t context;
    open_secure_rom_ake_context_initialize(&context, 0, 1);
    assert((unsigned char *)&context.sessions[0] -
        (unsigned char *)&context == 100);
    assert((unsigned char *)&context.transport_mode -
        (unsigned char *)&context == 500);
    assert(sep_ake_get_mode_capabilities(&context)->session_capacity == 5);
    assert(sep_ake_get_mode_capabilities(&context)->maximum_key_slot == 0x45);

    sep_ake_session_slot_t *slot = &context.sessions[0];
    slot->valid = 1;
    slot->key_slot = 7;
    slot->counter = 0x01020304;
    for (size_t index = 0; index < 8; ++index) {
        slot->nonce_seed[index] = (unsigned char)(0xa0 + index);
    }
    assert(sep_ake_find_session_slot(&context, 7) == slot);
    assert(sep_ake_find_session_slot(&context, 8) == NULL);

    const sep_ake_message_prefix_t prefix = {4, 7, 2, 1};
    unsigned char nonce[12];
    unsigned char aad[8];
    sep_ake_build_ccm_nonce(slot, nonce);
    sep_ake_build_ccm_aad(slot, &prefix, aad);
    const unsigned char expected_nonce[12] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        1, 2, 3, 4
    };
    const unsigned char expected_aad[8] = {4, 7, 2, 1, 1, 2, 3, 4};
    assert(memcmp(nonce, expected_nonce, sizeof(nonce)) == 0);
    assert(memcmp(aad, expected_aad, sizeof(aad)) == 0);

    assert(sep_ake_timeout_for_transport_mode1(0, 0) == 710000);
    assert(sep_ake_timeout_for_transport_mode1(0, 1) == 510000);
    assert(sep_ake_timeout_for_transport_modes_0_3_4(
        &(sep_ake_message_prefix_t){3, 0, 0, 0}, 0) == 1000000);
    assert(sep_ake_timeout_for_transport_mode5(
        &(sep_ake_message_prefix_t){3, 0, 0xff, 0}, 0) == 342000);
}

static void test_record_authentication(void) {
    unsigned char key[32];
    unsigned char record[64];
    unsigned char tag[16];
    for (size_t index = 0; index < sizeof(key); ++index) {
        key[index] = (unsigned char)(index * 7 + 3);
    }
    for (size_t index = 0; index < sizeof(record); ++index) {
        record[index] = (unsigned char)(index * 11 + 1);
    }
    record[4] = 1;
    store_crc(record);
    sep_ake_compute_record_types_1_2_authenticator(record, key, tag);
    memcpy(record + 48, tag, sizeof(tag));
    assert(sep_ake_verify_record_crc16(record));
    assert(sep_ake_verify_record_authenticator(record, key, sizeof(key)));
    record[40] ^= 0x80;
    assert(!sep_ake_verify_record_authenticator(record, key, sizeof(key)));
    record[40] ^= 0x80;
    record[5] ^= 1;
    assert(!sep_ake_verify_record_crc16(record));

    for (size_t index = 0; index < sizeof(record); ++index) {
        record[index] = (unsigned char)(0xd3 - index);
    }
    record[4] = 9;
    record[10] = 0x27;
    store_crc(record);
    sep_ake_compute_record_type_9_authenticator(record, key, tag);
    memcpy(record + 14, tag, sizeof(tag));
    assert(sep_ake_verify_record_authenticator(record, key, sizeof(key)));
    record[63] ^= 1;
    assert(!sep_ake_verify_record_authenticator(record, key, sizeof(key)));
}

static void test_record_service_fixture(void) {
    unsigned char sp_key[32];
    unsigned char authentication_key[32];
    unsigned char record[64] = {0};
    unsigned char output[32];
    sep_ake_derive_record_service_keys(
        sp_key,
        sizeof(sp_key),
        authentication_key,
        sizeof(authentication_key),
        service_context,
        sizeof(service_context)
    );
    for (size_t index = 0; index < 32; ++index) {
        record[32 + index] = (unsigned char)(0x80 + index);
    }
    record[4] = 9;
    record[10] = 0x35;
    store_crc(record);
    sep_ake_compute_record_type_9_authenticator(
        record,
        authentication_key,
        record + 14
    );
    open_secure_rom_ake_record_service_load_record(17, record);
    assert(sep_ake_select_record(17));
    sep_ake_cache_record_metadata(17);
    assert(sep_ake_find_authenticated_record(0x3509, output));
    assert(memcmp(output, record + 32, sizeof(output)) == 0);
    assert(sep_ake_prepare_type9_record_table(0x35));
    assert(sep_ake_read_prepared_table_word(0) != 0);
    sep_ake_close_record_service();
    assert(sep_ake_record_service_is_closed());
}

static void test_failure_record_cache_guard(void) {
    sep_ake_transport_failure_record_t accepted = {{0}};
    accepted.bytes[4] = 0x51;
    sep_ake_cache_transport_failure_record_if_reserved_zero(NULL, &accepted);
    assert(sep_ake_get_cached_transport_failure_record().bytes[4] == 0x51);
    sep_ake_transport_failure_record_t rejected = {{0}};
    rejected.bytes[4] = 0x82;
    rejected.bytes[43] = 1;
    sep_ake_cache_transport_failure_record_if_reserved_zero(NULL, &rejected);
    assert(sep_ake_get_cached_transport_failure_record().bytes[4] == 0x51);
}

int main(void) {
    test_context_layout_and_state();
    test_record_authentication();
    test_failure_record_cache_guard();
    test_record_service_fixture();
    puts("ake record tests passed");
}
