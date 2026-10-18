#include "open_secure_rom/ake.h"

#include "open_secure_rom/aes.h"
#include "open_secure_rom/cmac.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    abort();
}

void sep_delay_microseconds(sep_u32 microseconds) {
    (void)microseconds;
}

void sep_ake_cache_transport_failure_record_if_reserved_zero(
    const void *site_tag,
    const sep_ake_transport_failure_record_t *record
) {
    (void)site_tag;
    (void)record;
}

typedef struct transport_fixture {
    sep_ake_context_t *context;
    unsigned char key_material[32];
    unsigned char record[64];
    unsigned char metadata[32];
    unsigned command_count[10];
} transport_fixture_t;

static void encrypt_response(
    const sep_ake_session_slot_t *slot,
    const sep_ake_message_prefix_t *prefix,
    const unsigned char *plaintext,
    size_t length,
    unsigned char *ciphertext,
    unsigned char tag[16]
) {
    unsigned char nonce[12];
    unsigned char aad[8];
    sep_ake_build_ccm_nonce(slot, nonce);
    sep_ake_build_ccm_aad(slot, prefix, aad);
    assert(sep_ccccm_one_shot(sep_ccaes_ccm_encrypt_mode(), 32,
        slot->response_key, sizeof(nonce), nonce, length, plaintext,
        ciphertext, sizeof(aad), aad, 16, tag) == 0);
}

static sep_bool recorded_exchange(
    unsigned char transport_id,
    const unsigned char *request,
    size_t request_size,
    unsigned char *response,
    size_t response_size,
    sep_bool retry,
    void *opaque
) {
    transport_fixture_t *fixture = opaque;
    (void)transport_id;
    (void)retry;
    assert(request_size >= 4 && response_size >= 4);
    ++fixture->command_count[request[0]];
    memset(response, 0, response_size);
    response[0] = request[0];
    response[1] = request[1];
    response[3] = 0x80;
    if (request[0] == 1) {
        static const unsigned char mac_label[16] = {
            'A', 'K', 'E', '_', 'M', 'A', 'C', 'K', 'e', 'y', '\n', '\n',
            '\n', '\n', '\n', '\n'
        };
        unsigned char mac_key[32];
        assert(request_size == 116 && response_size == 116);
        for (size_t index = 0; index < 96; ++index) {
            response[20 + index] = (unsigned char)(0xf0 - index);
        }
        assert(sep_ake_kbkdf_cmac_derive(fixture->key_material, mac_label,
            request, mac_key, sizeof(mac_key)));
        sep_u64 storage[64] = {0};
        sep_cccmac_ctx_t *cmac = (sep_cccmac_ctx_t *)(void *)storage;
        assert(sep_cccmac_init(sep_ccaes_cbc_encrypt_mode(), cmac, 32,
            mac_key) == 0);
        assert(sep_cccmac_update(cmac, 4, response) == 0);
        assert(sep_cccmac_update(cmac, 96, request + 20) == 0);
        assert(sep_cccmac_update(cmac, 96, response + 20) == 0);
        assert(sep_cccmac_final_generate(cmac, 16, response + 4) == 0);
    } else if (request[0] == 4) {
        assert(response_size == 84);
        encrypt_response(
            fixture->context->active_session,
            (const sep_ake_message_prefix_t *)(const void *)response,
            fixture->record,
            sizeof(fixture->record),
            response + 20,
            response + 4
        );
    } else if (request[0] == 6) {
        assert(response_size == 52);
        encrypt_response(
            fixture->context->active_session,
            (const sep_ake_message_prefix_t *)(const void *)response,
            fixture->metadata,
            sizeof(fixture->metadata),
            response + 20,
            response + 4
        );
    }
    return 1;
}

int sep_ccec_import_pub(
    const sep_ccec_cp_t *curve,
    size_t length,
    const unsigned char *encoded,
    sep_ccec_pub_ctx_t *key
) {
    (void)curve;
    (void)length;
    (void)encoded;
    (void)key;
    return -1;
}

int sep_ccecdh_compute_shared_secret(
    sep_ccec_full_ctx_t *private_key,
    sep_ccec_pub_ctx_t *public_key,
    size_t *length,
    unsigned char *output,
    sep_ccrng_state_t *rng
) {
    (void)private_key;
    (void)public_key;
    (void)length;
    (void)output;
    (void)rng;
    return -1;
}

const sep_ccec_cp_t *sep_ccec_cp_384(void) {
    return NULL;
}

int main(void) {
    sep_ake_context_t context;
    transport_fixture_t fixture = {.context = &context};
    for (size_t index = 0; index < sizeof(fixture.key_material); ++index) {
        fixture.key_material[index] = (unsigned char)(index + 1);
    }
    for (size_t index = 0; index < sizeof(fixture.record); ++index) {
        fixture.record[index] = (unsigned char)(0x40 + index);
    }
    for (size_t index = 0; index < sizeof(fixture.metadata); ++index) {
        fixture.metadata[index] = (unsigned char)(0xa0 + index);
    }
    open_secure_rom_ake_context_initialize(&context, 0, 3);
    open_secure_rom_ake_set_transport_exchange(recorded_exchange, &fixture);
    assert(sep_ake_connect_key_slot(&context, 7, fixture.key_material, 32));
    assert(fixture.command_count[1] == 1);
    sep_ake_session_slot_t *slot = sep_ake_find_session_slot(&context, 7);
    assert(slot != NULL && slot->counter == 0);

    const sep_ake_message_prefix_t response_prefix = {4, 7, 0, 0x80};
    unsigned char plaintext[16];
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    unsigned char tag[16];
    memset(plaintext, 0x5a, sizeof(plaintext));
    encrypt_response(
        slot,
        &response_prefix,
        plaintext,
        sizeof(plaintext),
        ciphertext,
        tag
    );
    assert(sep_ake_ccm_decrypt_and_verify_response(slot, &response_prefix,
        ciphertext, sizeof(ciphertext), tag, decrypted));
    assert(memcmp(plaintext, decrypted, sizeof(plaintext)) == 0);
    tag[0] ^= 1;
    assert(!sep_ake_ccm_decrypt_and_verify_response(slot, &response_prefix,
        ciphertext, sizeof(ciphertext), tag, decrypted));

    unsigned char record[64];
    sep_ake_read_authenticated_record(&context, 7, 1, record);
    assert(slot->counter == 1);
    assert(memcmp(record, fixture.record, sizeof(record)) == 0);
    unsigned char metadata[32];
    sep_ake_read_record_metadata(
        &context,
        7,
        2,
        0,
        metadata,
        sizeof(metadata)
    );
    assert(slot->counter == 2);
    assert(memcmp(metadata, fixture.metadata, sizeof(metadata)) == 0);

    sep_ake_disconnect_key_slot(&context, 7);
    assert(sep_ake_find_session_slot(&context, 7) == NULL);
    sep_ake_finalize_transport(&context);
    assert(fixture.command_count[2] == 1);
    assert(fixture.command_count[8] == 1);
    puts("ake transport tests passed");
}
