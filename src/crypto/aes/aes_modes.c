#include "open_secure_rom/aes.h"

_Static_assert(sizeof(sep_ccmode_cbc_t) == 40, "CBC descriptor ABI");
_Static_assert(sizeof(sep_ccmode_ecb_t) == 40, "ECB descriptor ABI");
_Static_assert(sizeof(sep_ccmode_ccm_t) == 88, "CCM descriptor ABI");
_Static_assert(sizeof(sep_ccccm_ctx_t) == 280, "CCM context ABI");
_Static_assert(sizeof(sep_ccccm_nonce_t) == 96, "CCM nonce ABI");
_Static_assert(offsetof(sep_ccccm_ctx_t, key) == 16, "CCM key offset ABI");
_Static_assert(offsetof(sep_ccccm_nonce_t, state) == 64, "CCM state offset ABI");
_Static_assert(offsetof(sep_ccccm_nonce_t, nonce_length) == 80, "CCM nonce length offset ABI");

enum {
    CCM_STATE_IV = 1,
    CCM_STATE_AAD = 4,
    CCM_STATE_TEXT = 5,
    CCM_INVALID_CALL_SEQUENCE = -68,
};

static void mode_copy(
    void *destination,
    const void *source,
    sep_size_t length
) {
    sep_u8 *output = destination;
    const sep_u8 *input = source;
    for (sep_size_t index = 0; index < length; ++index) {
        output[index] = input[index];
    }
}

static void mode_clear(void *destination, sep_size_t length) {
    sep_u8 *bytes = destination;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

static int ecb_key_init(
    const void *mode,
    void *context,
    sep_size_t key_length,
    const void *key
) {
    return sep_ccaes_ecb_encrypt_key_with_length_check(
        mode,
        context,
        key_length,
        key
    );
}

static int ecb_encrypt_blocks(
    const void *context,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    return sep_ccaes_arm_encrypt_ecb(context, block_count, input, output);
}

static int cbc_key_init(
    const void *mode,
    void *context,
    sep_size_t key_length,
    const void *key
) {
    return sep_ccaes_cbc_encrypt_key_with_length_check(
        mode,
        context,
        key_length,
        key
    );
}

static int cbc_encrypt_blocks(
    const void *context,
    void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    return sep_ccaes_arm_encrypt_cbc(
        context,
        iv,
        block_count,
        input,
        output
    );
}

static const sep_ccmode_ecb_t aes_ecb_encrypt_descriptor = {
    .size = sizeof(sep_aes_key_context_t),
    .block_size = 16,
    .init = ecb_key_init,
    .ecb = ecb_encrypt_blocks,
    .custom = 0,
};

static const sep_ccmode_cbc_t aes_cbc_encrypt_descriptor = {
    .size = sizeof(sep_aes_key_context_t),
    .block_size = 16,
    .init = cbc_key_init,
    .cbc = cbc_encrypt_blocks,
    .custom = 0,
};

static const sep_ccmode_ccm_t aes_ccm_encrypt_descriptor = {
    .size = sizeof(sep_ccccm_ctx_t),
    .nonce_size = sizeof(sep_ccccm_nonce_t),
    .block_size = 1,
    .init = sep_ccmode_ccm_init,
    .set_iv = sep_ccmode_ccm_set_iv,
    .cbcmac = sep_ccmode_ccm_cbcmac,
    .ccm = sep_ccmode_ccm_encrypt_veneer,
    .finalize = sep_ccmode_ccm_finalize,
    .reset = sep_ccmode_ccm_reset,
    .custom = &aes_ecb_encrypt_descriptor,
    .encrypt = 1,
};

static const sep_ccmode_ccm_t aes_ccm_decrypt_descriptor = {
    .size = sizeof(sep_ccccm_ctx_t),
    .nonce_size = sizeof(sep_ccccm_nonce_t),
    .block_size = 1,
    .init = sep_ccmode_ccm_init,
    .set_iv = sep_ccmode_ccm_set_iv,
    .cbcmac = sep_ccmode_ccm_cbcmac,
    .ccm = sep_ccmode_ccm_decrypt_veneer,
    .finalize = sep_ccmode_ccm_finalize,
    .reset = sep_ccmode_ccm_reset,
    .custom = &aes_ecb_encrypt_descriptor,
    .encrypt = 0,
};

const sep_ccmode_cbc_t *sep_ccaes_cbc_encrypt_mode(void) {
    return &aes_cbc_encrypt_descriptor;
}

const sep_ccmode_ecb_t *sep_ccaes_ecb_encrypt_mode(void) {
    return &aes_ecb_encrypt_descriptor;
}

const sep_ccmode_ccm_t *sep_ccaes_ccm_encrypt_mode(void) {
    return &aes_ccm_encrypt_descriptor;
}

const sep_ccmode_ccm_t *sep_ccaes_ccm_decrypt_mode(void) {
    return &aes_ccm_decrypt_descriptor;
}

int sep_cccbc_init_internal(
    const sep_ccmode_cbc_t *mode,
    void *context,
    sep_size_t key_length,
    const void *key
) {
    return mode->init(mode, context, key_length, key);
}

int sep_cccbc_set_iv_internal(
    const sep_ccmode_cbc_t *mode,
    void *iv_context,
    const void *iv
) {
    if (iv != 0) {
        mode_copy(iv_context, iv, mode->block_size);
    } else {
        mode_clear(iv_context, mode->block_size);
    }
    return 0;
}

int sep_cccbc_update_internal(
    const sep_ccmode_cbc_t *mode,
    const void *context,
    void *iv_context,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    return mode->cbc(context, iv_context, block_count, input, output);
}

int sep_cccbc_one_shot_explicit_internal(
    const sep_ccmode_cbc_t *mode,
    sep_size_t key_length,
    const void *key,
    sep_size_t iv_length,
    const void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    if ((iv_length != mode->block_size && iv_length != 0) ||
        (iv == 0 && iv_length != 0)) {
        return -7;
    }

    sep_u64 context_words[(mode->size + 7) / 8];
    sep_u64 iv_words[(mode->block_size + 7) / 8];
    mode_clear(context_words, mode->size);
    mode_clear(iv_words, mode->block_size);
    int result = mode->init(mode, context_words, key_length, key);
    if (result == 0) {
        if (iv != 0) {
            mode_copy(iv_words, iv, mode->block_size);
        }
        result = mode->cbc(
            context_words,
            iv_words,
            block_count,
            input,
            output
        );
    }
    mode_clear(context_words, mode->size);
    return result;
}

int sep_cccbc_one_shot(
    const sep_ccmode_cbc_t *mode,
    sep_size_t key_length,
    const void *key,
    const void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    return sep_cccbc_one_shot_explicit_internal(
        mode,
        key_length,
        key,
        iv != 0 ? mode->block_size : 0,
        iv,
        block_count,
        input,
        output
    );
}

void sep_ccmode_copy_ccm_descriptor(
    sep_ccmode_ccm_t *destination,
    const sep_ccmode_ccm_t *source
) {
    destination->size = source->size;
    destination->nonce_size = source->nonce_size;
    destination->block_size = source->block_size;
    destination->init = source->init;
    destination->set_iv = source->set_iv;
    destination->cbcmac = source->cbcmac;
    destination->ccm = source->ccm;
    destination->finalize = source->finalize;
    destination->reset = source->reset;
    destination->custom = source->custom;
    destination->encrypt = source->encrypt;
}

int sep_ccmode_ccm_init(
    const sep_ccmode_ccm_t *mode,
    sep_ccccm_ctx_t *context,
    sep_size_t raw_key_length,
    const void *raw_key
) {
    context->ecb = mode->custom;
    context->ecb->init(
        context->ecb,
        &context->key,
        raw_key_length,
        raw_key
    );
    return 0;
}

static void ccm_encrypt_one(
    const sep_ccccm_ctx_t *context,
    const sep_u8 input[16],
    sep_u8 output[16]
) {
    context->ecb->ecb(&context->key, 1, input, output);
}

static void ccm_increment_counter(
    sep_u8 counter[16],
    sep_size_t counter_length
) {
    for (sep_size_t index = 16; index > 16 - counter_length; --index) {
        counter[index - 1] = (sep_u8)(counter[index - 1] + 1U);
        if (counter[index - 1] != 0) {
            break;
        }
    }
}

int sep_ccmode_ccm_set_iv(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t nonce_length,
    const void *nonce,
    sep_size_t tag_length,
    sep_size_t authenticated_data_length,
    sep_size_t plaintext_length
) {
    if (context->ecb->block_size != 16) {
        return -1;
    }
    nonce_context->state = CCM_STATE_IV;
    mode_clear(nonce_context->stream, 16);
    nonce_context->stream_offset = 0;

    if (tag_length < 4 || tag_length > 16 || (tag_length & 1U) != 0 ||
        nonce_length < 7 || nonce_length > 13 ||
        (authenticated_data_length >> 32) != 0) {
        return -1;
    }
    const sep_size_t counter_length = 15 - nonce_length;
    if (counter_length < 8 &&
        (plaintext_length >> (8 * counter_length)) != 0) {
        return -1;
    }

    /* B0 authenticates the declared lengths before any streaming input. */
    nonce_context->nonce_length = nonce_length;
    nonce_context->tag_length = tag_length;
    mode_clear(nonce_context->mac_block, 16);
    nonce_context->mac_block[0] = (sep_u8)(
        (authenticated_data_length != 0 ? 0x40U : 0U) |
        ((tag_length / 2 - 1) << 3) |
        (counter_length - 1)
    );
    mode_copy(nonce_context->mac_block + 1, nonce, nonce_length);
    sep_size_t remaining = plaintext_length;
    for (sep_size_t index = 0; index < counter_length; ++index) {
        nonce_context->mac_block[15 - index] = (sep_u8)remaining;
        remaining >>= 8;
    }
    ccm_encrypt_one(
        context,
        nonce_context->mac_block,
        nonce_context->mac_block
    );

    mode_clear(nonce_context->counter, 16);
    nonce_context->counter[0] = (sep_u8)(counter_length - 1);
    mode_copy(nonce_context->counter + 1, nonce, nonce_length);
    ccm_encrypt_one(
        context,
        nonce_context->counter,
        nonce_context->tag_mask
    );

    /* SP800-38C uses compact and extended prefixes for the AAD length. */
    if (authenticated_data_length == 0) {
        nonce_context->mac_offset = 0;
        nonce_context->state = CCM_STATE_TEXT;
    } else if (authenticated_data_length < 0xff00U) {
        nonce_context->mac_block[0] ^=
            (sep_u8)(authenticated_data_length >> 8);
        nonce_context->mac_block[1] ^= (sep_u8)authenticated_data_length;
        nonce_context->mac_offset = 2;
        nonce_context->state = CCM_STATE_AAD;
    } else {
        nonce_context->mac_block[0] ^= 0xff;
        nonce_context->mac_block[1] ^= 0xfe;
        nonce_context->mac_block[2] ^=
            (sep_u8)(authenticated_data_length >> 24);
        nonce_context->mac_block[3] ^=
            (sep_u8)(authenticated_data_length >> 16);
        nonce_context->mac_block[4] ^=
            (sep_u8)(authenticated_data_length >> 8);
        nonce_context->mac_block[5] ^= (sep_u8)authenticated_data_length;
        nonce_context->mac_offset = 6;
        nonce_context->state = CCM_STATE_AAD;
    }
    return 0;
}

void sep_ccmode_ccm_macdata(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_u32 new_block,
    sep_size_t byte_count,
    const void *input
) {
    if (new_block != 0) {
        ccm_encrypt_one(
            context,
            nonce_context->mac_block,
            nonce_context->mac_block
        );
        nonce_context->mac_offset = 0;
    }

    const sep_u8 *bytes = input;
    sep_size_t consumed = 0;
    while (consumed < byte_count) {
        sep_size_t amount = 16 - nonce_context->mac_offset;
        if (amount > byte_count - consumed) {
            amount = byte_count - consumed;
        }
        for (sep_size_t index = 0; index < amount; ++index) {
            nonce_context->mac_block[nonce_context->mac_offset + index] ^=
                bytes[consumed + index];
        }
        consumed += amount;
        nonce_context->mac_offset =
            (sep_u32)((nonce_context->mac_offset + amount) & 15U);
        if (nonce_context->mac_offset == 0) {
            ccm_encrypt_one(
                context,
                nonce_context->mac_block,
                nonce_context->mac_block
            );
        }
    }
}

int sep_ccmode_ccm_cbcmac(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input
) {
    if (byte_count != 0 && nonce_context->state != CCM_STATE_AAD) {
        return CCM_INVALID_CALL_SEQUENCE;
    }
    sep_ccmode_ccm_macdata(context, nonce_context, 0, byte_count, input);
    return 0;
}

void sep_ccmode_ccm_crypt(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
) {
    const sep_u8 *input_bytes = input;
    sep_u8 *output_bytes = output;
    const sep_size_t counter_length = 15 - nonce_context->nonce_length;
    for (sep_size_t index = 0; index < byte_count; ++index) {
        if (nonce_context->stream_offset == 0) {
            ccm_increment_counter(nonce_context->counter, counter_length);
            ccm_encrypt_one(
                context,
                nonce_context->counter,
                nonce_context->stream
            );
        }
        output_bytes[index] = input_bytes[index] ^
            nonce_context->stream[nonce_context->stream_offset];
        nonce_context->stream_offset =
            (nonce_context->stream_offset + 1U) & 15U;
    }
}

static int ccm_begin_text(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context
) {
    /* AAD and plaintext occupy distinct CBC-MAC blocks at the transition. */
    if (nonce_context->state == CCM_STATE_AAD) {
        if (nonce_context->mac_offset != 0) {
            ccm_encrypt_one(
                context,
                nonce_context->mac_block,
                nonce_context->mac_block
            );
            nonce_context->mac_offset = 0;
        }
        nonce_context->state = CCM_STATE_TEXT;
    }
    return nonce_context->state == CCM_STATE_TEXT
        ? 0
        : CCM_INVALID_CALL_SEQUENCE;
}

int sep_ccmode_ccm_encrypt(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
) {
    int result = ccm_begin_text(context, nonce_context);
    if (result != 0) {
        return result;
    }
    sep_ccmode_ccm_macdata(context, nonce_context, 0, byte_count, input);
    sep_ccmode_ccm_crypt(context, nonce_context, byte_count, input, output);
    return 0;
}

int sep_ccmode_ccm_decrypt(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
) {
    int result = ccm_begin_text(context, nonce_context);
    if (result != 0) {
        return result;
    }
    sep_ccmode_ccm_crypt(context, nonce_context, byte_count, input, output);
    sep_ccmode_ccm_macdata(context, nonce_context, 0, byte_count, output);
    return 0;
}

int sep_ccmode_ccm_encrypt_veneer(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
) {
    return sep_ccmode_ccm_encrypt(
        context,
        nonce_context,
        byte_count,
        input,
        output
    );
}

int sep_ccmode_ccm_decrypt_veneer(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
) {
    return sep_ccmode_ccm_decrypt(
        context,
        nonce_context,
        byte_count,
        input,
        output
    );
}

int sep_ccmode_ccm_finalize(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    void *tag
) {
    if (nonce_context->state == CCM_STATE_IV) {
        return CCM_INVALID_CALL_SEQUENCE;
    }
    if (nonce_context->mac_offset != 0) {
        ccm_encrypt_one(
            context,
            nonce_context->mac_block,
            nonce_context->mac_block
        );
    }
    for (sep_size_t index = 0; index < 16; ++index) {
        nonce_context->tag_mask[index] ^= nonce_context->mac_block[index];
    }
    mode_copy(tag, nonce_context->tag_mask, nonce_context->tag_length);
    return 0;
}

int sep_ccmode_ccm_reset(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context
) {
    (void)context;
    mode_clear(nonce_context->tag_mask, 16);
    mode_clear(nonce_context->stream, 16);
    nonce_context->stream_offset = 0;
    nonce_context->mac_offset = 0;
    nonce_context->nonce_length = 0;
    nonce_context->tag_length = 0;
    nonce_context->state = CCM_STATE_IV;
    return 0;
}

static void ccm_blocks(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length,
    sep_bool decrypt
) {
    const sep_aes_key_context_t *key = key_schedule;
    const sep_u8 *input_bytes = input;
    sep_u8 *output_bytes = output;
    sep_u8 *tag_bytes = tag;
    sep_u8 *counter_bytes = counter;
    /* CCM decrypts with the AES encryption schedule and authenticates plaintext. */
    for (sep_size_t block = 0; block < block_count; ++block) {
        sep_u8 source[16];
        sep_u8 stream[16];
        sep_u8 plaintext[16];
        mode_copy(source, input_bytes + 16 * block, 16);
        ccm_increment_counter(counter_bytes, counter_length);
        sep_ccaes_arm_encrypt_ecb(key, 1, counter_bytes, stream);
        for (sep_size_t index = 0; index < 16; ++index) {
            plaintext[index] = decrypt != 0
                ? (sep_u8)(source[index] ^ stream[index])
                : source[index];
            output_bytes[16 * block + index] = decrypt != 0
                ? plaintext[index]
                : (sep_u8)(plaintext[index] ^ stream[index]);
            tag_bytes[index] ^= plaintext[index];
        }
        sep_ccaes_arm_encrypt_ecb(key, 1, tag_bytes, tag_bytes);
    }
}

void sep_ccm128_encrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
) {
    ccm_blocks(
        input,
        output,
        tag,
        block_count,
        key_schedule,
        counter,
        counter_length,
        0
    );
}

void sep_ccm128_decrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
) {
    ccm_blocks(
        input,
        output,
        tag,
        block_count,
        key_schedule,
        counter,
        counter_length,
        1
    );
}

void sep_ccm192_encrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
) {
    ccm_blocks(
        input,
        output,
        tag,
        block_count,
        key_schedule,
        counter,
        counter_length,
        0
    );
}

void sep_ccm192_decrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
) {
    ccm_blocks(
        input,
        output,
        tag,
        block_count,
        key_schedule,
        counter,
        counter_length,
        1
    );
}

void sep_ccm256_encrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
) {
    ccm_blocks(
        input,
        output,
        tag,
        block_count,
        key_schedule,
        counter,
        counter_length,
        0
    );
}

void sep_ccm256_decrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
) {
    ccm_blocks(
        input,
        output,
        tag,
        block_count,
        key_schedule,
        counter,
        counter_length,
        1
    );
}

int sep_ccccm_one_shot_internal(
    const sep_ccmode_ccm_t *mode,
    sep_size_t key_length,
    const void *key,
    sep_size_t nonce_length,
    const void *nonce,
    sep_size_t data_length,
    const void *input,
    void *output,
    sep_size_t associated_data_length,
    const void *associated_data,
    sep_size_t tag_length,
    void *tag
) {
    sep_u64 context_words[(mode->size + 7) / 8];
    sep_u64 nonce_words[(mode->nonce_size + 7) / 8];
    mode_clear(context_words, mode->size);
    mode_clear(nonce_words, mode->nonce_size);
    sep_ccccm_ctx_t *context = (sep_ccccm_ctx_t *)context_words;
    sep_ccccm_nonce_t *nonce_context = (sep_ccccm_nonce_t *)nonce_words;

    int result = mode->init(mode, context, key_length, key);
    if (result == 0) {
        result = mode->set_iv(
            context,
            nonce_context,
            nonce_length,
            nonce,
            tag_length,
            associated_data_length,
            data_length
        );
    }
    if (result == 0) {
        result = mode->cbcmac(
            context,
            nonce_context,
            associated_data_length,
            associated_data
        );
    }
    if (result == 0) {
        result = mode->ccm(context, nonce_context, data_length, input, output);
    }
    if (result == 0) {
        result = mode->finalize(context, nonce_context, tag);
    }
    mode_clear(context_words, mode->size);
    mode_clear(nonce_words, mode->nonce_size);
    return result;
}

int sep_ccccm_one_shot(
    const sep_ccmode_ccm_t *mode,
    sep_size_t key_length,
    const void *key,
    sep_size_t nonce_length,
    const void *nonce,
    sep_size_t data_length,
    const void *input,
    void *output,
    sep_size_t associated_data_length,
    const void *associated_data,
    sep_size_t tag_length,
    void *tag
) {
    return sep_ccccm_one_shot_internal(
        mode,
        key_length,
        key,
        nonce_length,
        nonce,
        data_length,
        input,
        output,
        associated_data_length,
        associated_data,
        tag_length,
        tag
    );
}
