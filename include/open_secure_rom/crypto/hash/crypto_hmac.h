#ifndef OPEN_SECURE_ROM_CRYPTO_HMAC_H
#define OPEN_SECURE_ROM_CRYPTO_HMAC_H

#include "open_secure_rom/crypto_digest.h"

enum {
    SEP_CCHMAC_CONTEXT_SIZE = 272,
};

struct sep_cchmac_ctx {
    sep_u8 bytes[SEP_CCHMAC_CONTEXT_SIZE];
} __attribute__((aligned(8)));

_Static_assert(
    sizeof(sep_cchmac_ctx_t) == SEP_CCHMAC_CONTEXT_SIZE,
    "HMAC context capacity"
);

void sep_hmac_by_bit_length(
    sep_size_t digest_bit_length,
    const void *data,
    sep_size_t data_length,
    const void *key,
    sep_size_t key_length,
    sep_u8 *mac,
    sep_size_t mac_length
);
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
);
void sep_cchmac_internal(
    const sep_ccdigest_info_t *digest,
    sep_size_t key_length,
    const void *key,
    sep_size_t data_length,
    const void *data,
    sep_u8 *mac
);
void sep_cchmac(
    const sep_ccdigest_info_t *digest,
    sep_size_t key_length,
    const void *key,
    sep_size_t data_length,
    const void *data,
    sep_u8 *mac
);
void sep_cchmac_final_internal(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_u8 *mac
);
void sep_cchmac_final(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_u8 *mac
);
void sep_cchmac_init_internal(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
);
void sep_cchmac_init(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
);
void sep_cchmac_update_internal(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
);
void sep_cchmac_update(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
);
int sep_cchkdf_expand_internal(
    const sep_ccdigest_info_t *digest,
    sep_size_t prk_length,
    const void *prk,
    sep_size_t info_length,
    const void *info,
    sep_size_t derived_key_length,
    void *derived_key
);
int sep_cchkdf_internal(
    const sep_ccdigest_info_t *digest,
    sep_size_t ikm_length,
    const void *ikm,
    sep_size_t salt_length,
    const void *salt,
    sep_size_t info_length,
    const void *info,
    sep_size_t derived_key_length,
    void *derived_key
);
int sep_cchkdf(
    const sep_ccdigest_info_t *digest,
    sep_size_t ikm_length,
    const void *ikm,
    sep_size_t salt_length,
    const void *salt,
    sep_size_t info_length,
    const void *info,
    sep_size_t derived_key_length,
    void *derived_key
);
sep_checked_bytes32_t sep_checked_bytes32_hmac_sha256(
    const void *data,
    sep_size_t data_length,
    const void *key,
    sep_size_t key_length
);
sep_bool sep_hmac_sha256_tag_matches(
    const sep_u8 key[32],
    const void *message,
    sep_size_t message_length,
    const void *tag,
    sep_size_t tag_length
);

#endif
