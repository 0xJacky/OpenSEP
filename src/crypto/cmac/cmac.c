#include "open_secure_rom/cmac.h"

_Static_assert(sizeof(sep_cccmac_ctx_t) == 80, "CMAC header ABI");
_Static_assert(offsetof(sep_cccmac_ctx_t, block_length) == 48, "CMAC buffered length ABI");
_Static_assert(offsetof(sep_cccmac_ctx_t, cbc) == 64, "CMAC descriptor offset ABI");
_Static_assert(offsetof(sep_cccmac_ctx_t, mode_context) == 72, "CMAC mode context offset ABI");

static void cmac_copy(
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

static void cmac_clear(void *destination, sep_size_t length) {
    sep_u8 *bytes = destination;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

static sep_size_t cmac_context_size(const sep_ccmode_cbc_t *cbc) {
    return SEP_CCMAC_CONTEXT_SIZE(cbc);
}

static void *cmac_cipher_context(sep_cccmac_ctx_t *context) {
    return context->mode_context;
}

static void *cmac_iv_context(sep_cccmac_ctx_t *context) {
    return context->mode_context + context->cbc->size;
}

static void cmac_double(sep_u8 output[16], const sep_u8 input[16]) {
    sep_u8 carry = 0;
    const sep_u8 high_bit = input[0] >> 7;
    for (sep_size_t index = 16; index != 0; --index) {
        const sep_u8 value = input[index - 1];
        output[index - 1] = (sep_u8)((value << 1) | carry);
        carry = value >> 7;
    }
    output[15] ^= (sep_u8)(0x87U & (0U - high_bit));
}

int sep_cccmac_generate_subkeys(
    const sep_ccmode_cbc_t *cbc,
    sep_size_t key_length,
    const void *key,
    sep_u8 subkey1[16],
    sep_u8 subkey2[16]
) {
    sep_u8 zero[16] = {0};
    sep_u8 encrypted_zero[16] = {0};
    int result = sep_cccbc_one_shot_explicit_internal(
        cbc,
        key_length,
        key,
        cbc->block_size,
        zero,
        1,
        zero,
        encrypted_zero
    );
    if (result == 0) {
        cmac_double(subkey1, encrypted_zero);
        cmac_double(subkey2, subkey1);
        cmac_clear(encrypted_zero, sizeof(encrypted_zero));
    }
    return result;
}

int sep_cccmac_init_internal(
    const sep_ccmode_cbc_t *cbc,
    sep_cccmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
) {
    if (key_length != 16 && key_length != 24 && key_length != 32) {
        return -7;
    }

    context->cbc = cbc;
    sep_cccbc_init_internal(
        cbc,
        cmac_cipher_context(context),
        key_length,
        key
    );
    sep_u8 zero_iv[16] = {0};
    sep_cccbc_set_iv_internal(cbc, cmac_iv_context(context), zero_iv);
    context->block_length = 0;
    context->processed_length = 0;
    return sep_cccmac_generate_subkeys(
        cbc,
        key_length,
        key,
        context->subkey1,
        context->subkey2
    );
}

int sep_cccmac_init(
    const sep_ccmode_cbc_t *cbc,
    sep_cccmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
) {
    return sep_cccmac_init_internal(cbc, context, key_length, key);
}

int sep_cccmac_update_internal(
    sep_cccmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
) {
    if (data_length == 0 || data == 0) {
        return 0;
    }
    if (context->block_length > 16) {
        return -1;
    }

    const sep_u8 *input = data;
    const sep_ccmode_cbc_t *cbc = context->cbc;
    sep_u8 output[16 * 16];
    if (context->block_length != 0) {
        sep_size_t amount = 16 - context->block_length;
        if (amount > data_length) {
            amount = data_length;
        }
        cmac_copy(context->block + context->block_length, input, amount);
        context->block_length += amount;
        input += amount;
        data_length -= amount;
        if (data_length == 0) {
            return 0;
        }
        sep_cccbc_update_internal(
            cbc,
            cmac_cipher_context(context),
            cmac_iv_context(context),
            1,
            context->block,
            output
        );
        context->processed_length += 16;
    }

    sep_size_t block_count = (data_length - 1) >> 4;
    while (block_count != 0) {
        sep_size_t process_count = block_count < 16 ? block_count : 16;
        sep_cccbc_update_internal(
            cbc,
            cmac_cipher_context(context),
            cmac_iv_context(context),
            process_count,
            input,
            output
        );
        input += 16 * process_count;
        block_count -= process_count;
        context->processed_length += 16 * process_count;
    }

    sep_size_t remaining = ((data_length - 1) & 15U) + 1;
    cmac_copy(context->block, input, remaining);
    context->block_length = remaining;
    cmac_clear(output, sizeof(output));
    return 0;
}

int sep_cccmac_update(
    sep_cccmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
) {
    return sep_cccmac_update_internal(context, data_length, data);
}

int sep_cccmac_final_generate_internal(
    sep_cccmac_ctx_t *context,
    sep_size_t mac_length,
    void *mac
) {
    const sep_ccmode_cbc_t *cbc = context->cbc;
    const sep_size_t clear_length = cmac_context_size(cbc);
    const sep_size_t final_length = context->block_length;
    context->processed_length += final_length;
    int result = -1;

    if (final_length <= 16 &&
        (final_length != 0 || context->processed_length == 0) &&
        mac_length >= 1 && mac_length <= 16) {
        sep_u8 *subkey = context->subkey2;
        if (final_length == 16) {
            subkey = context->subkey1;
        } else {
            cmac_clear(context->block + final_length, 16 - final_length);
            context->block[final_length] = 0x80;
        }
        for (sep_size_t index = 0; index < 16; ++index) {
            context->block[index] ^= subkey[index];
        }
        sep_u8 full_mac[16];
        sep_cccbc_update_internal(
            cbc,
            cmac_cipher_context(context),
            cmac_iv_context(context),
            1,
            context->block,
            full_mac
        );
        cmac_copy(mac, full_mac, mac_length);
        cmac_clear(full_mac, sizeof(full_mac));
        result = 0;
    }

    cmac_clear(context, clear_length);
    return result;
}

int sep_cccmac_final_generate(
    sep_cccmac_ctx_t *context,
    sep_size_t mac_length,
    void *mac
) {
    return sep_cccmac_final_generate_internal(context, mac_length, mac);
}

static int cmac_compare(
    const void *left,
    const void *right,
    sep_size_t length
) {
    const sep_u8 *left_bytes = left;
    const sep_u8 *right_bytes = right;
    sep_u8 difference = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        difference |= left_bytes[index] ^ right_bytes[index];
    }
    return difference;
}

int sep_cccmac_final_verify_internal(
    sep_cccmac_ctx_t *context,
    sep_size_t expected_mac_length,
    const void *expected_mac
) {
    sep_u8 full_mac[16];
    int result = sep_cccmac_final_generate_internal(
        context,
        sizeof(full_mac),
        full_mac
    );
    if (result == 0) {
        result = cmac_compare(expected_mac, full_mac, expected_mac_length) == 0
            ? 0
            : -5;
    }
    cmac_clear(full_mac, sizeof(full_mac));
    return result;
}

int sep_cccmac_final_verify(
    sep_cccmac_ctx_t *context,
    sep_size_t expected_mac_length,
    const void *expected_mac
) {
    return sep_cccmac_final_verify_internal(
        context,
        expected_mac_length,
        expected_mac
    );
}

void sep_ccnistkdf_ctr_cmac_prf_eval(
    sep_cccmac_ctx_t *cmac,
    sep_u8 counter_width,
    sep_u32 counter,
    sep_size_t fixed_data_length,
    const void *fixed_data,
    void *result
) {
    const sep_u8 encoded_counter[4] = {
        (sep_u8)(counter >> 24),
        (sep_u8)(counter >> 16),
        (sep_u8)(counter >> 8),
        (sep_u8)counter,
    };
    const sep_size_t counter_length = counter_width >> 3;
    sep_cccmac_update_internal(
        cmac,
        counter_length,
        encoded_counter + 4 - counter_length
    );
    sep_cccmac_update_internal(cmac, fixed_data_length, fixed_data);
    sep_cccmac_final_generate_internal(cmac, cmac->cbc->block_size, result);
}

int sep_ccnistkdf_ctr_cmac_fixed_internal(
    const sep_ccmode_cbc_t *cbc,
    sep_u8 counter_width,
    sep_size_t kdk_length,
    const void *kdk,
    sep_size_t fixed_data_length,
    const void *fixed_data,
    sep_size_t derived_key_length,
    void *derived_key
) {
    if (derived_key_length == 0 || derived_key == 0 || kdk_length == 0 ||
        kdk == 0 || (counter_width != 8 && counter_width != 16 &&
        counter_width != 24 && counter_width != 32)) {
        return -7;
    }

    const sep_size_t block_size = cbc->block_size;
    const sep_size_t complete_blocks = derived_key_length / block_size;
    const sep_size_t partial_length = derived_key_length % block_size;
    const sep_size_t evaluated_blocks = complete_blocks +
        (partial_length != 0 ? 1 : 0);
    if (evaluated_blocks >= (UINT64_C(1) << counter_width)) {
        return -7;
    }

    const sep_size_t context_size = cmac_context_size(cbc);
    sep_u64 cache_words[(context_size + 7) / 8];
    sep_u64 work_words[(context_size + 7) / 8];
    sep_cccmac_ctx_t *cache = (sep_cccmac_ctx_t *)cache_words;
    sep_cccmac_ctx_t *work = (sep_cccmac_ctx_t *)work_words;
    cmac_clear(cache, context_size);
    cmac_clear(work, context_size);
    int result = sep_cccmac_init_internal(cbc, cache, kdk_length, kdk);
    if (result != 0) {
        cmac_clear(cache, context_size);
        cmac_clear(work, context_size);
        return result;
    }

    sep_u8 *output = derived_key;
    for (sep_size_t block = 1; block <= complete_blocks; ++block) {
        cmac_copy(work, cache, context_size);
        sep_ccnistkdf_ctr_cmac_prf_eval(
            work,
            counter_width,
            (sep_u32)block,
            fixed_data_length,
            fixed_data,
            output
        );
        output += block_size;
    }
    if (partial_length != 0) {
        sep_u8 last_block[16];
        cmac_copy(work, cache, context_size);
        sep_ccnistkdf_ctr_cmac_prf_eval(
            work,
            counter_width,
            (sep_u32)evaluated_blocks,
            fixed_data_length,
            fixed_data,
            last_block
        );
        cmac_copy(output, last_block, partial_length);
        cmac_clear(last_block, sizeof(last_block));
    }

    cmac_clear(cache, context_size);
    cmac_clear(work, context_size);
    return 0;
}

int sep_ccnistkdf_ctr_cmac_fixed(
    const sep_ccmode_cbc_t *cbc,
    sep_u8 counter_width,
    sep_size_t kdk_length,
    const void *kdk,
    sep_size_t fixed_data_length,
    const void *fixed_data,
    sep_size_t derived_key_length,
    void *derived_key
) {
    return sep_ccnistkdf_ctr_cmac_fixed_internal(
        cbc,
        counter_width,
        kdk_length,
        kdk,
        fixed_data_length,
        fixed_data,
        derived_key_length,
        derived_key
    );
}
