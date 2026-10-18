#include "open_secure_rom/rsa.h"

#include "open_secure_rom/crypto_fault.h"
#include "open_secure_rom/crypto_workspace.h"
#include "open_secure_rom/der.h"
#include "open_secure_rom/runtime.h"

enum {
    RSA_INVALID_INPUT = -23,
    RSA_SIGNATURE_MISMATCH = -146,
    /*
     * 0x7dcdc05e: the flag value callers pass to accept a signature shorter
     * than the modulus.  It is a value of the ROM's interface, as observed in
     * AVPSEPBooter, kept so callers written against that interface agree.
     */
    RSA_ALLOW_SHORT_SIGNATURE = 2110636126,
};

/*
 * The fault-detection canary a successful PKCS #1 verification writes back.
 * Like the flag above it is a value of the ROM's interface, as observed in
 * AVPSEPBooter; callers compare against these exact bytes.
 */
static const sep_u8 rsa_pkcs1_fault_canary[16] = {
    0xea, 0xc5, 0x4a, 0x7c, 0x9f, 0x28, 0xdf, 0x10,
    0xb6, 0xe9, 0x3e, 0xb9, 0x1c, 0xd3, 0x3a, 0xc5,
};

static sep_u64 *rsa_modulus(sep_ccrsa_pub_ctx_t *key) {
    return key->storage;
}

static const sep_u64 *rsa_const_modulus(const sep_ccrsa_pub_ctx_t *key) {
    return key->storage;
}

static sep_u64 *rsa_exponent(sep_ccrsa_pub_ctx_t *key) {
    return key->storage + 2 * key->modulus_field.n + 1;
}

static void rsa_zero_bytes(void *destination, sep_size_t length) {
    sep_u8 *bytes = destination;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

int sep_ccrsa_make_pub(
    sep_ccrsa_pub_ctx_t *public_key,
    sep_size_t exponent_length,
    const sep_u8 *exponent,
    sep_size_t modulus_length,
    const sep_u8 *modulus
) {
    const sep_size_t n = public_key->modulus_field.n;
    sep_u64 workspace_words[5 * n + 3];
    sep_cc_ws_t workspace = {workspace_words, 5 * n + 3, 0};
    rsa_zero_bytes(workspace_words, sizeof(workspace_words));

    if (sep_ccn_read_uint_public_value(
            n, rsa_modulus(public_key), modulus_length, modulus) != 0 ||
        sep_ccn_read_uint_public_value(
            n, rsa_exponent(public_key), exponent_length, exponent) != 0) {
        rsa_zero_bytes(workspace_words, sizeof(workspace_words));
        return RSA_INVALID_INPUT;
    }

    const int result = sep_cczp_mm_init_ws(
        &workspace,
        &public_key->modulus_field,
        n,
        NULL
    );
    rsa_zero_bytes(workspace_words, sizeof(workspace_words));
    return result;
}

int sep_rsa_public_key_set_components(
    sep_ccrsa_pub_ctx_t *public_key,
    sep_size_t modulus_length,
    const sep_u8 *modulus,
    sep_size_t exponent_length,
    const sep_u8 *exponent
) {
    if (public_key == NULL || modulus == NULL || exponent == NULL ||
        ((uintptr_t)public_key & 7U) != 0) {
        sep_fatal_wait_loop();
    }

    while (modulus_length != 0 && modulus[0] == 0) {
        ++modulus;
        --modulus_length;
    }
    if (modulus_length > SIZE_MAX - 7) {
        sep_fatal_wait_loop();
    }

    const sep_size_t n = (modulus_length + 7) >> 3;
    if (n > public_key->modulus_field.n) {
        return -1;
    }
    public_key->modulus_field.n = n;
    return sep_ccrsa_make_pub(
        public_key,
        exponent_length,
        exponent,
        modulus_length,
        modulus
    );
}

int sep_rsa_public_key_decode_pkcs1(
    sep_ccrsa_pub_ctx_t *public_key,
    sep_size_t der_length,
    const sep_u8 *der_bytes
) {
    static const sep_der_item_spec_t public_key_specs[2] = {
        {0, SEP_DER_TAG_INTEGER, 0x100},
        {sizeof(sep_der_item_t), SEP_DER_TAG_INTEGER, 0x100},
    };
    struct {
        sep_der_item_t modulus;
        sep_der_item_t exponent;
    } components;
    const sep_size_t recovered_length = (sep_u32)der_length;
    const sep_der_item_t der = {der_bytes, recovered_length};
    if (sep_der_parse_sequence(
            &der,
            2,
            public_key_specs,
            &components,
            sizeof(components)
        ) != SEP_DER_SUCCESS) {
        return -1;
    }
    return sep_rsa_public_key_set_components(
        public_key,
        components.modulus.length,
        components.modulus.data,
        components.exponent.length,
        components.exponent.data
    );
}

int sep_ccrsa_emsa_pkcs1v15_verify_canary_out(
    sep_size_t encoded_message_length,
    const sep_u8 *encoded_message,
    sep_size_t digest_length,
    const sep_u8 *digest,
    const sep_u8 *oid,
    sep_u8 fault_canary[16]
) {
    rsa_zero_bytes(fault_canary, 16);
    const sep_size_t oid_content_length = oid == NULL ? 0 : oid[1];
    const sep_size_t encoded_digest_length = oid == NULL
        ? digest_length
        : digest_length + oid_content_length + 10;
    if (encoded_message_length < encoded_digest_length + 11) {
        return RSA_INVALID_INPUT;
    }

    sep_u8 mismatch = encoded_message[0] | (encoded_message[1] ^ 1U);
    const sep_size_t padding_length =
        encoded_message_length - encoded_digest_length - 3;
    for (sep_size_t index = 0; index < padding_length; ++index) {
        mismatch |= (sep_u8)~encoded_message[2 + index];
    }

    const sep_u8 *cursor = encoded_message + 2 + padding_length;
    mismatch |= *cursor++;
    if (oid != NULL) {
        mismatch |= *cursor++ ^ 0x30U;
        mismatch |= *cursor++ ^ (sep_u8)(encoded_digest_length - 2);
        mismatch |= *cursor++ ^ 0x30U;
        mismatch |= *cursor++ ^ (sep_u8)(oid_content_length + 4);
        mismatch |= (sep_u8)sep_cc_cmp_safe_internal(
            oid_content_length + 2,
            cursor,
            oid
        );
        cursor += oid_content_length + 2;
        mismatch |= *cursor++ ^ 0x05U;
        mismatch |= *cursor++;
        mismatch |= *cursor++ ^ 0x04U;
        mismatch |= *cursor++ ^ (sep_u8)digest_length;
    }

    sep_cc_fault_canary_set(
        fault_canary,
        rsa_pkcs1_fault_canary,
        digest_length,
        digest,
        cursor
    );
    mismatch |= (sep_u8)sep_cc_cmp_safe_internal(
        digest_length,
        cursor,
        digest
    );
    return mismatch;
}

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
) {
    rsa_zero_bytes(fault_canary, 16);
    const sep_size_t n = key->modulus_field.n;
    const sep_u64 *modulus = rsa_const_modulus(key);
    const sep_size_t encoded_message_length = sep_ccn_write_uint_size(
        n,
        modulus
    );
    const sep_bool valid_signature_length =
        signature_length_validation == RSA_ALLOW_SHORT_SIGNATURE
            ? signature_length <= encoded_message_length
            : signature_length == encoded_message_length;
    if (!valid_signature_length) {
        return RSA_INVALID_INPUT;
    }

    const sep_size_t saved_offset = workspace->offset;
    sep_u64 *signature_value = sep_cc_ws_alloc(workspace, n);
    sep_u64 *encoded_message = sep_cc_ws_alloc(workspace, n);
    rsa_zero_bytes(
        signature_value,
        sizeof(sep_u64) * (workspace->offset - saved_offset)
    );

    int result;
    if (sep_ccn_read_uint(
            n,
            signature_value,
            signature_length,
            signature
        ) != 0) {
        result = RSA_INVALID_INPUT;
    } else {
        result = sep_cczp_inv_field_ws(
            workspace,
            &key->modulus_field,
            encoded_message,
            signature_value
        );
        if (result == 0) {
            sep_ccn_swap(n, encoded_message);
            result = sep_ccrsa_emsa_pkcs1v15_verify_canary_out(
                encoded_message_length,
                (const sep_u8 *)encoded_message + sizeof(sep_u64) * n -
                    encoded_message_length,
                digest_length,
                digest,
                oid,
                fault_canary
            );
            if (result != 0) {
                result = RSA_SIGNATURE_MISMATCH;
            } else {
                sep_u8 canary_check = 0x89;
                for (sep_size_t index = 0; index < 16; ++index) {
                    canary_check ^= fault_canary[index];
                }
                result = canary_check;
            }
        }
    }

    rsa_zero_bytes(
        &workspace->ctx[saved_offset],
        sizeof(sep_u64) * (workspace->offset - saved_offset)
    );
    workspace->offset = saved_offset;
    return result;
}

int sep_ccrsa_verify_pkcs1v15_digest(
    sep_ccrsa_pub_ctx_t *key,
    const sep_u8 *oid,
    sep_size_t digest_length,
    const sep_u8 *digest,
    sep_size_t signature_length,
    const sep_u8 *signature,
    sep_u8 fault_canary[16]
) {
    const sep_size_t workspace_limb_count = 11 * key->modulus_field.n;
    sep_u64 workspace_words[workspace_limb_count];
    sep_cc_ws_t workspace = {
        workspace_words,
        workspace_limb_count,
        0,
    };
    rsa_zero_bytes(workspace_words, sizeof(workspace_words));
    sep_u8 local_fault_canary[16] = {0};
    sep_u8 *canary = fault_canary == NULL ? local_fault_canary : fault_canary;
    rsa_zero_bytes(canary, 16);
    const int result = sep_ccrsa_verify_pkcs1v15_internal_ws(
        &workspace,
        key,
        oid,
        digest_length,
        digest,
        signature_length,
        signature,
        0,
        local_fault_canary
    );
    if (fault_canary != NULL) {
        for (sep_size_t index = 0; index < 16; ++index) {
            fault_canary[index] = local_fault_canary[index];
        }
    }
    rsa_zero_bytes(workspace_words, sizeof(workspace_words));
    rsa_zero_bytes(local_fault_canary, sizeof(local_fault_canary));
    return result;
}

int sep_rsa_verify_pkcs1v15_digest_checked(
    sep_ccrsa_pub_ctx_t *key,
    const sep_u8 *oid,
    sep_size_t digest_length,
    const sep_u8 *digest,
    sep_size_t signature_length,
    const sep_u8 *signature,
    sep_u8 fault_canary[16]
) {
    if (key == NULL || digest == NULL || signature == NULL) {
        sep_fatal_wait_loop();
    }
    return sep_ccrsa_verify_pkcs1v15_digest(
        key,
        oid,
        digest_length,
        digest,
        signature_length,
        signature,
        fault_canary
    );
}
