#ifndef OPEN_SECURE_ROM_RSA_H
#define OPEN_SECURE_ROM_RSA_H

#include "open_secure_rom/bignum_modular.h"

typedef struct sep_ccrsa_pub_ctx {
    sep_cczp_t modulus_field;
    sep_u64 storage[];
} sep_ccrsa_pub_ctx_t;

#define SEP_CCRSA_PUB_CONTEXT_SIZE(limb_count) \
    (sizeof(sep_cczp_t) + sizeof(sep_u64) * (3u * (limb_count) + 1u))

int sep_rsa_public_key_set_components(
    sep_ccrsa_pub_ctx_t *public_key,
    sep_size_t modulus_length,
    const sep_u8 *modulus,
    sep_size_t exponent_length,
    const sep_u8 *exponent
);
int sep_rsa_public_key_decode_pkcs1(
    sep_ccrsa_pub_ctx_t *public_key,
    sep_size_t der_length,
    const sep_u8 *der_bytes
);
int sep_rsa_verify_pkcs1v15_digest_checked(
    sep_ccrsa_pub_ctx_t *key,
    const sep_u8 *oid,
    sep_size_t digest_length,
    const sep_u8 *digest,
    sep_size_t signature_length,
    const sep_u8 *signature,
    sep_u8 fault_canary[16]
);
int sep_ccrsa_make_pub(
    sep_ccrsa_pub_ctx_t *public_key,
    sep_size_t exponent_length,
    const sep_u8 *exponent,
    sep_size_t modulus_length,
    const sep_u8 *modulus
);
int sep_ccrsa_emsa_pkcs1v15_verify_canary_out(
    sep_size_t encoded_message_length,
    const sep_u8 *encoded_message,
    sep_size_t digest_length,
    const sep_u8 *digest,
    const sep_u8 *oid,
    sep_u8 fault_canary[16]
);
int sep_ccrsa_verify_pkcs1v15_digest(
    sep_ccrsa_pub_ctx_t *key,
    const sep_u8 *oid,
    sep_size_t digest_length,
    const sep_u8 *digest,
    sep_size_t signature_length,
    const sep_u8 *signature,
    sep_u8 fault_canary[16]
);
int sep_ccrsa_verify_pkcs1v15_internal_ws(
    sep_cc_ws_t *workspace,
    sep_ccrsa_pub_ctx_t *key,
    const sep_u8 *oid,
    sep_size_t digest_length,
    const sep_u8 *digest,
    sep_size_t signature_length,
    const sep_u8 *signature,
    int signature_length_validation,
    sep_u8 fault_canary[16]
);

#endif
