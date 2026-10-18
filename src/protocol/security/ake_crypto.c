#include "open_secure_rom/ake.h"

#include "open_secure_rom/aes.h"
#include "open_secure_rom/cmac.h"
#include "open_secure_rom/crypto_digest.h"
#include "open_secure_rom/crypto_hmac.h"
#include "open_secure_rom/runtime.h"

static void require(sep_bool condition) {
    if (!condition) {
        sep_fatal_wait_loop();
    }
}

static sep_cccmac_ctx_t *cmac_context(sep_u64 storage[64]) {
    sep_memzero(storage, 64 * sizeof(*storage));
    return (sep_cccmac_ctx_t *)(void *)storage;
}

sep_bool sep_ake_kbkdf_cmac_derive(
    const sep_u8 *cmac_key,
    const sep_u8 *label,
    const sep_u8 *context,
    sep_u8 *output,
    sep_size_t output_size
) {
    require(cmac_key != NULL && label != NULL && context != NULL &&
        output != NULL && output_size != 0);
    sep_u8 fixed_data[20];
    sep_memmove(fixed_data, label, 16);
    sep_memmove(fixed_data + 16, context, 4);
    const int status = sep_ccnistkdf_ctr_cmac_fixed(
        sep_ccaes_cbc_encrypt_mode(),
        16,
        32,
        cmac_key,
        sizeof(fixed_data),
        fixed_data,
        output_size,
        output
    );
    sep_memzero(fixed_data, sizeof(fixed_data));
    return status == 0;
}

void sep_ake_compute_connect_request_cmac(
    sep_u8 *output,
    const sep_u8 *key,
    const sep_ake_message_prefix_t *prefix,
    const sep_u8 *public_key
) {
    require(output != NULL && key != NULL && prefix != NULL &&
        public_key != NULL);
    sep_u64 storage[64];
    sep_cccmac_ctx_t *cmac = cmac_context(storage);
    require(sep_cccmac_init(sep_ccaes_cbc_encrypt_mode(), cmac, 32, key)
        == 0);
    require(sep_cccmac_update(cmac, sizeof(*prefix), prefix) == 0);
    require(sep_cccmac_update(cmac, 96, public_key) == 0);
    require(sep_cccmac_final_generate(cmac, 16, output) == 0);
    sep_memzero(storage, sizeof(storage));
}

sep_bool sep_ake_verify_connect_response_cmac(
    const sep_u8 *expected_cmac,
    const sep_u8 *key,
    const sep_ake_message_prefix_t *prefix,
    const sep_u8 *request_public_key,
    const sep_u8 *response_public_key
) {
    require(expected_cmac != NULL && key != NULL && prefix != NULL &&
        request_public_key != NULL && response_public_key != NULL);
    sep_u64 storage[64];
    sep_cccmac_ctx_t *cmac = cmac_context(storage);
    require(sep_cccmac_init(sep_ccaes_cbc_encrypt_mode(), cmac, 32, key)
        == 0);
    require(sep_cccmac_update(cmac, sizeof(*prefix), prefix) == 0);
    require(sep_cccmac_update(cmac, 96, request_public_key) == 0);
    require(sep_cccmac_update(cmac, 96, response_public_key) == 0);
    const sep_bool valid = sep_cccmac_final_verify(cmac, 16, expected_cmac)
        == 0;
    sep_memzero(storage, sizeof(storage));
    return valid;
}

void sep_ake_ccm_authenticate_empty_request_and_advance_counter(
    sep_ake_session_slot_t *slot,
    const sep_ake_message_prefix_t *prefix,
    sep_u8 *tag
) {
    require(slot != NULL && prefix != NULL && tag != NULL &&
        slot->counter < 0xffffe);
    sep_u8 nonce[12];
    sep_u8 aad[8];
    sep_ake_build_ccm_nonce(slot, nonce);
    sep_ake_build_ccm_aad(slot, prefix, aad);
    require(sep_ccccm_one_shot(sep_ccaes_ccm_encrypt_mode(), 32,
        slot->request_key, sizeof(nonce), nonce, 0, NULL, NULL,
        sizeof(aad), aad, 16, tag) == 0);
    ++slot->counter;
    sep_memzero(nonce, sizeof(nonce));
    sep_memzero(aad, sizeof(aad));
}

sep_bool sep_ake_ccm_decrypt_and_verify_response(
    const sep_ake_session_slot_t *slot,
    const sep_ake_message_prefix_t *prefix,
    const void *ciphertext,
    sep_size_t ciphertext_length,
    const sep_u8 *tag,
    void *plaintext
) {
    require(slot != NULL && prefix != NULL && tag != NULL &&
        ((ciphertext == NULL && plaintext == NULL && ciphertext_length == 0) ||
         (ciphertext != NULL && plaintext != NULL && ciphertext_length != 0)) &&
        (ciphertext_length & 15) == 0);
    sep_u8 nonce[12];
    sep_u8 aad[8];
    sep_u8 computed_tag[16];
    sep_ake_build_ccm_nonce(slot, nonce);
    sep_ake_build_ccm_aad(slot, prefix, aad);
    require(sep_ccccm_one_shot(sep_ccaes_ccm_decrypt_mode(), 32,
        slot->response_key, sizeof(nonce), nonce, ciphertext_length,
        ciphertext, plaintext, sizeof(aad), aad, sizeof(computed_tag),
        computed_tag) == 0);
    const sep_bool valid = sep_constant_time_memcmp(tag, computed_tag,
        sizeof(computed_tag)) == 0;
    sep_memzero(nonce, sizeof(nonce));
    sep_memzero(aad, sizeof(aad));
    sep_memzero(computed_tag, sizeof(computed_tag));
    return valid;
}

void sep_ake_derive_session_material_from_p384_ecdh(
    sep_u8 *output,
    const void *local_private_key,
    const sep_u8 *peer_public_key,
    const sep_u8 *extractor_key,
    const sep_u8 *context,
    const sep_u8 *label,
    void *rng_state
) {
    require(output != NULL && local_private_key != NULL &&
        peer_public_key != NULL && extractor_key != NULL && context != NULL &&
        label != NULL && rng_state != NULL);
    sep_u8 peer_storage[SEP_CCEC_PUB_CTX_BYTES(6)]
        __attribute__((aligned(16)));
    sep_ccec_pub_ctx_t *peer = (sep_ccec_pub_ctx_t *)(void *)peer_storage;
    sep_u8 encoded_peer[97];
    sep_u8 shared_secret[48];
    sep_u8 extracted_key[32];
    sep_size_t shared_secret_size = sizeof(shared_secret);
    encoded_peer[0] = 4;
    sep_memmove(encoded_peer + 1, peer_public_key, 96);
    require(sep_ccec_import_pub(sep_ccec_cp_384(), sizeof(encoded_peer),
        encoded_peer, peer) == 0);
    require(sep_ccecdh_compute_shared_secret(
        (sep_ccec_full_ctx_t *)(void *)local_private_key, peer,
        &shared_secret_size, shared_secret,
        (sep_ccrng_state_t *)rng_state) == 0);
    sep_cchmac(
        sep_ccsha256_di(),
        32,
        extractor_key,
        shared_secret_size,
        shared_secret,
        extracted_key
    );
    require(sep_ake_kbkdf_cmac_derive(extracted_key, label, context, output,
        72));
    sep_memzero(peer_storage, sizeof(peer_storage));
    sep_memzero(encoded_peer, sizeof(encoded_peer));
    sep_memzero(shared_secret, sizeof(shared_secret));
    sep_memzero(extracted_key, sizeof(extracted_key));
}
