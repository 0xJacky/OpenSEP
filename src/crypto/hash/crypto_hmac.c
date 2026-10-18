#include "open_secure_rom/crypto_hmac.h"

#include "open_secure_rom/runtime.h"

enum {
    SEP_CCERR_PARAMETER = -4300,
};

static sep_size_t digest_context_size(
    const sep_ccdigest_info_t *digest
) {
    return 8 + digest->state_size + digest->block_size + 4;
}

static sep_size_t aligned_digest_context_size(
    const sep_ccdigest_info_t *digest
) {
    return (digest_context_size(digest) + 7) & ~(sep_size_t)7;
}

static sep_ccdigest_ctx_t *inner_context(sep_cchmac_ctx_t *context) {
    return (sep_ccdigest_ctx_t *)context;
}

static sep_u8 *outer_state(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context
) {
    return &context->bytes[aligned_digest_context_size(digest)];
}

static void require_context_capacity(const sep_ccdigest_info_t *digest) {
    if (aligned_digest_context_size(digest) + digest->state_size >
        SEP_CCHMAC_CONTEXT_SIZE) {
        sep_fatal_wait_loop();
    }
}

void sep_cchmac_init_internal(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
) {
    require_context_capacity(digest);
    sep_memzero(context, SEP_CCHMAC_CONTEXT_SIZE);

    sep_u8 normalized_key[SEP_CCDIGEST_MAX_STATE_SIZE];
    const sep_u8 *key_bytes = key;
    if (key_length > digest->block_size) {
        sep_ccdigest(digest, key_length, key, normalized_key);
        key_bytes = normalized_key;
        key_length = digest->output_size;
    }

    sep_u8 pad[SEP_CCDIGEST_MAX_BLOCK_SIZE];
    sep_memset(pad, 0x5c, digest->block_size);
    for (sep_size_t index = 0; index < key_length; ++index) {
        pad[index] ^= key_bytes[index];
    }

    sep_ccdigest_ctx_t outer;
    sep_memzero(&outer, sizeof(outer));
    sep_ccdigest_init(digest, &outer);
    sep_ccdigest_update(digest, &outer, digest->block_size, pad);
    sep_memmove(
        outer_state(digest, context),
        &outer.bytes[8],
        digest->state_size
    );

    for (sep_size_t index = 0; index < digest->block_size; ++index) {
        pad[index] ^= 0x5c ^ 0x36;
    }
    sep_ccdigest_init(digest, inner_context(context));
    sep_ccdigest_update(
        digest,
        inner_context(context),
        digest->block_size,
        pad
    );

    sep_memzero(&outer, sizeof(outer));
    sep_memzero(pad, sizeof(pad));
    sep_memzero(normalized_key, sizeof(normalized_key));
}

void sep_cchmac_init(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
) {
    sep_cchmac_init_internal(digest, context, key_length, key);
}

void sep_cchmac_update_internal(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
) {
    sep_ccdigest_update(
        digest,
        inner_context(context),
        data_length,
        data
    );
}

void sep_cchmac_update(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
) {
    sep_cchmac_update_internal(digest, context, data_length, data);
}

void sep_cchmac_final_internal(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_u8 *mac
) {
    sep_u8 inner_digest[SEP_CCDIGEST_MAX_STATE_SIZE];
    digest->final(digest, inner_context(context), inner_digest);

    sep_ccdigest_ctx_t outer;
    sep_memzero(&outer, sizeof(outer));
    sep_ccdigest_init(digest, &outer);
    sep_memmove(&outer.bytes[8], outer_state(digest, context), digest->state_size);
    *(sep_u64 *)&outer.bytes[0] = (sep_u64)digest->block_size * 8;
    *(sep_u32 *)&outer.bytes[8 + digest->state_size + digest->block_size] = 0;
    sep_ccdigest_update(digest, &outer, digest->output_size, inner_digest);
    digest->final(digest, &outer, mac);

    sep_memzero(&outer, sizeof(outer));
    sep_memzero(inner_digest, sizeof(inner_digest));
}

void sep_cchmac_final(
    const sep_ccdigest_info_t *digest,
    sep_cchmac_ctx_t *context,
    sep_u8 *mac
) {
    sep_cchmac_final_internal(digest, context, mac);
}

void sep_cchmac_internal(
    const sep_ccdigest_info_t *digest,
    sep_size_t key_length,
    const void *key,
    sep_size_t data_length,
    const void *data,
    sep_u8 *mac
) {
    sep_cchmac_ctx_t context;
    sep_cchmac_init_internal(digest, &context, key_length, key);
    sep_cchmac_update_internal(digest, &context, data_length, data);
    sep_cchmac_final_internal(digest, &context, mac);
    sep_memzero(&context, sizeof(context));
}

void sep_cchmac(
    const sep_ccdigest_info_t *digest,
    sep_size_t key_length,
    const void *key,
    sep_size_t data_length,
    const void *data,
    sep_u8 *mac
) {
    sep_cchmac_internal(digest, key_length, key, data_length, data, mac);
}

void sep_hmac_by_bit_length(
    sep_size_t digest_bit_length,
    const void *data,
    sep_size_t data_length,
    const void *key,
    sep_size_t key_length,
    sep_u8 *mac,
    sep_size_t mac_length
) {
    if (mac_length > SIZE_MAX / 8 ||
        digest_bit_length != mac_length * 8) {
        sep_fatal_wait_loop();
    }
    sep_cchmac(
        sep_digest_info_for_bit_length(digest_bit_length),
        key_length,
        key,
        data_length,
        data,
        mac
    );
}

int sep_cchkdf_expand_internal(
    const sep_ccdigest_info_t *digest,
    sep_size_t prk_length,
    const void *prk,
    sep_size_t info_length,
    const void *info,
    sep_size_t derived_key_length,
    void *derived_key
) {
    const sep_size_t block_count = derived_key_length == 0
        ? 0
        : 1 + (derived_key_length - 1) / digest->output_size;
    if (block_count > 255 || prk_length < digest->output_size) {
        return SEP_CCERR_PARAMETER;
    }

    sep_u8 previous[SEP_CCDIGEST_MAX_STATE_SIZE];
    sep_u8 *output = derived_key;
    sep_size_t previous_length = 0;
    sep_size_t offset = 0;
    for (sep_size_t index = 1; index <= block_count; ++index) {
        sep_cchmac_ctx_t context;
        sep_cchmac_init_internal(digest, &context, prk_length, prk);
        sep_cchmac_update_internal(
            digest,
            &context,
            previous_length,
            previous
        );
        sep_cchmac_update_internal(digest, &context, info_length, info);
        const sep_u8 counter = (sep_u8)index;
        sep_cchmac_update_internal(digest, &context, 1, &counter);
        sep_cchmac_final_internal(digest, &context, previous);
        sep_memzero(&context, sizeof(context));

        sep_size_t copy_length = derived_key_length - offset;
        if (copy_length > digest->output_size) {
            copy_length = digest->output_size;
        }
        sep_memmove(&output[offset], previous, copy_length);
        offset += copy_length;
        previous_length = digest->output_size;
    }
    sep_memzero(previous, sizeof(previous));
    return 0;
}

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
) {
    sep_u8 zero_salt[SEP_CCDIGEST_MAX_STATE_SIZE] = {0};
    if (salt_length == 0) {
        salt = zero_salt;
        salt_length = digest->output_size;
    }
    sep_u8 prk[SEP_CCDIGEST_MAX_STATE_SIZE];
    sep_cchmac(digest, salt_length, salt, ikm_length, ikm, prk);
    const int status = sep_cchkdf_expand_internal(
        digest,
        digest->output_size,
        prk,
        info_length,
        info,
        derived_key_length,
        derived_key
    );
    sep_memzero(prk, sizeof(prk));
    return status;
}

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
) {
    return sep_cchkdf_internal(
        digest,
        ikm_length,
        ikm,
        salt_length,
        salt,
        info_length,
        info,
        derived_key_length,
        derived_key
    );
}

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
) {
    return sep_cchkdf(
        sep_digest_info_for_bit_length(digest_bit_length),
        ikm_length,
        ikm,
        salt_length,
        salt,
        info_length,
        info,
        derived_key_length,
        derived_key
    );
}

sep_checked_bytes32_t sep_checked_bytes32_hmac_sha256(
    const void *data,
    sep_size_t data_length,
    const void *key,
    sep_size_t key_length
) {
    sep_checked_bytes32_t result;
    sep_cchmac(
        sep_ccsha256_di(),
        key_length,
        key,
        data_length,
        data,
        result.bytes
    );
    result.initialized = 1;
    return result;
}

sep_bool sep_hmac_sha256_tag_matches(
    const sep_u8 key[32],
    const void *message,
    sep_size_t message_length,
    const void *tag,
    sep_size_t tag_length
) {
    if (tag_length > 32) {
        sep_fatal_wait_loop();
    }
    sep_u8 computed[32];
    sep_cchmac(
        sep_ccsha256_di(),
        32,
        key,
        message_length,
        message,
        computed
    );
    const sep_bool matches =
        sep_constant_time_memcmp(computed, tag, tag_length) == 0;
    sep_memzero(computed, sizeof(computed));
    return matches;
}
