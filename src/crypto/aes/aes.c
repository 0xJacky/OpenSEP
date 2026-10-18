#include "open_secure_rom/aes.h"

#include <stdint.h>

_Static_assert(sizeof(sep_aes_key_context_t) == 244, "AES key context ABI");
_Static_assert(offsetof(sep_aes_key_context_t, final_round_offset) == 240, "AES round offset ABI");

static const sep_u8 aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const sep_u8 aes_inverse_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static sep_u8 aes_multiply(sep_u8 left, sep_u8 right) {
    sep_u8 result = 0;
    while (right != 0) {
        if ((right & 1U) != 0) {
            result ^= left;
        }
        left = (sep_u8)((left << 1) ^ ((left & 0x80U) != 0 ? 0x1bU : 0));
        right >>= 1;
    }
    return result;
}

static void aes_add_round_key(sep_u8 state[16], const sep_u8 round_key[16]) {
    for (sep_size_t index = 0; index < 16; ++index) {
        state[index] ^= round_key[index];
    }
}

static void aes_sub_bytes(sep_u8 state[16]) {
    for (sep_size_t index = 0; index < 16; ++index) {
        state[index] = aes_sbox[state[index]];
    }
}

static void aes_inverse_sub_bytes(sep_u8 state[16]) {
    for (sep_size_t index = 0; index < 16; ++index) {
        state[index] = aes_inverse_sbox[state[index]];
    }
}

static void aes_shift_rows(sep_u8 state[16]) {
    const sep_u8 source[16] = {
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7],
        state[8], state[9], state[10], state[11],
        state[12], state[13], state[14], state[15],
    };
    for (sep_size_t row = 0; row < 4; ++row) {
        for (sep_size_t column = 0; column < 4; ++column) {
            state[4 * column + row] = source[4 * ((column + row) & 3U) + row];
        }
    }
}

static void aes_inverse_shift_rows(sep_u8 state[16]) {
    const sep_u8 source[16] = {
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7],
        state[8], state[9], state[10], state[11],
        state[12], state[13], state[14], state[15],
    };
    for (sep_size_t row = 0; row < 4; ++row) {
        for (sep_size_t column = 0; column < 4; ++column) {
            state[4 * column + row] =
                source[4 * ((column + 4 - row) & 3U) + row];
        }
    }
}

static void aes_mix_columns(sep_u8 state[16]) {
    for (sep_size_t column = 0; column < 4; ++column) {
        sep_u8 *value = &state[4 * column];
        const sep_u8 a = value[0];
        const sep_u8 b = value[1];
        const sep_u8 c = value[2];
        const sep_u8 d = value[3];
        value[0] = aes_multiply(a, 2) ^ aes_multiply(b, 3) ^ c ^ d;
        value[1] = a ^ aes_multiply(b, 2) ^ aes_multiply(c, 3) ^ d;
        value[2] = a ^ b ^ aes_multiply(c, 2) ^ aes_multiply(d, 3);
        value[3] = aes_multiply(a, 3) ^ b ^ c ^ aes_multiply(d, 2);
    }
}

static void aes_inverse_mix_columns(sep_u8 state[16]) {
    for (sep_size_t column = 0; column < 4; ++column) {
        sep_u8 *value = &state[4 * column];
        const sep_u8 a = value[0];
        const sep_u8 b = value[1];
        const sep_u8 c = value[2];
        const sep_u8 d = value[3];
        value[0] = aes_multiply(a, 14) ^ aes_multiply(b, 11) ^
            aes_multiply(c, 13) ^ aes_multiply(d, 9);
        value[1] = aes_multiply(a, 9) ^ aes_multiply(b, 14) ^
            aes_multiply(c, 11) ^ aes_multiply(d, 13);
        value[2] = aes_multiply(a, 13) ^ aes_multiply(b, 9) ^
            aes_multiply(c, 14) ^ aes_multiply(d, 11);
        value[3] = aes_multiply(a, 11) ^ aes_multiply(b, 13) ^
            aes_multiply(c, 9) ^ aes_multiply(d, 14);
    }
}

static void aes_copy(void *destination, const void *source, sep_size_t length) {
    sep_u8 *output = destination;
    const sep_u8 *input = source;
    for (sep_size_t index = 0; index < length; ++index) {
        output[index] = input[index];
    }
}

static void aes_expand_key(
    const sep_u8 *raw_key,
    sep_size_t raw_key_length,
    sep_aes_key_context_t *expanded_key
) {
    const sep_size_t round_count = raw_key_length / 4 + 6;
    const sep_size_t expanded_length = 16 * (round_count + 1);
    sep_u8 round_constant = 1;
    aes_copy(expanded_key->round_keys, raw_key, raw_key_length);

    for (sep_size_t generated = raw_key_length; generated < expanded_length;
         generated += 4) {
        sep_u8 temporary[4] = {
            expanded_key->round_keys[generated - 4],
            expanded_key->round_keys[generated - 3],
            expanded_key->round_keys[generated - 2],
            expanded_key->round_keys[generated - 1],
        };
        if ((generated % raw_key_length) == 0) {
            const sep_u8 first = temporary[0];
            temporary[0] = aes_sbox[temporary[1]] ^ round_constant;
            temporary[1] = aes_sbox[temporary[2]];
            temporary[2] = aes_sbox[temporary[3]];
            temporary[3] = aes_sbox[first];
            round_constant = aes_multiply(round_constant, 2);
        } else if (raw_key_length == 32 && (generated % 32) == 16) {
            for (sep_size_t index = 0; index < 4; ++index) {
                temporary[index] = aes_sbox[temporary[index]];
            }
        }
        for (sep_size_t index = 0; index < 4; ++index) {
            expanded_key->round_keys[generated + index] =
                expanded_key->round_keys[generated + index - raw_key_length] ^
                temporary[index];
        }
    }
    expanded_key->final_round_offset = (sep_u32)(round_count * 16);
}

static void aes_encrypt_block(
    const sep_aes_key_context_t *key,
    const sep_u8 input[16],
    sep_u8 output[16]
) {
    sep_u8 state[16];
    aes_copy(state, input, 16);
    aes_add_round_key(state, key->round_keys);
    const sep_size_t round_count = key->final_round_offset / 16;
    for (sep_size_t round = 1; round < round_count; ++round) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &key->round_keys[16 * round]);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &key->round_keys[key->final_round_offset]);
    aes_copy(output, state, 16);
}

static void aes_decrypt_block(
    const sep_aes_key_context_t *key,
    const sep_u8 input[16],
    sep_u8 output[16]
) {
    sep_u8 state[16];
    aes_copy(state, input, 16);
    const sep_size_t round_count = key->final_round_offset / 16;
    aes_add_round_key(state, &key->round_keys[key->final_round_offset]);
    for (sep_size_t round = round_count - 1; round != 0; --round) {
        aes_inverse_shift_rows(state);
        aes_inverse_sub_bytes(state);
        aes_inverse_mix_columns(state);
        aes_add_round_key(state, &key->round_keys[16 * round]);
    }
    aes_inverse_shift_rows(state);
    aes_inverse_sub_bytes(state);
    aes_add_round_key(state, key->round_keys);
    aes_copy(output, state, 16);
}

static sep_size_t aes_normalized_key_length(sep_size_t raw_key_length) {
    if ((int64_t)raw_key_length > 32) {
        return raw_key_length >> 3;
    }
    return raw_key_length;
}

static int aes_key_length_checked(
    sep_aes_key_context_t *key,
    sep_size_t raw_key_length,
    const void *raw_key,
    sep_bool decrypt
) {
    if ((int64_t)raw_key_length > 127) {
        if (raw_key_length != 128 && raw_key_length != 192 &&
            raw_key_length != 256) {
            return -7;
        }
    } else if (raw_key_length > 32 ||
        ((UINT64_C(0x101010000) >> raw_key_length) & 1U) == 0) {
        return -7;
    }
    return decrypt != 0
        ? sep_ccaes_arm_decrypt_key(0, key, raw_key_length, raw_key)
        : sep_ccaes_arm_encrypt_key(0, key, raw_key_length, raw_key);
}

sep_size_t sep_aes_key_length_bytes(sep_size_t key_bit_length) {
    if (key_bit_length == 128) {
        return 16;
    }
    if (key_bit_length == 192) {
        return 24;
    }
    if (key_bit_length == 256) {
        return 32;
    }
    __builtin_trap();
}

void sep_ccaes_arm_encrypt_key128(
    const void *raw_key,
    sep_aes_key_context_t *expanded_key
) {
    aes_expand_key(raw_key, 16, expanded_key);
}

void sep_ccaes_arm_encrypt_key192(
    const void *raw_key,
    sep_aes_key_context_t *expanded_key
) {
    aes_expand_key(raw_key, 24, expanded_key);
}

void sep_ccaes_arm_encrypt_key256(
    const void *raw_key,
    sep_aes_key_context_t *expanded_key
) {
    aes_expand_key(raw_key, 32, expanded_key);
}

int sep_ccaes_arm_encrypt_key(
    const void *mode,
    sep_aes_key_context_t *expanded_key,
    sep_size_t raw_key_length,
    const void *raw_key
) {
    (void)mode;
    switch (aes_normalized_key_length(raw_key_length)) {
    case 16:
        sep_ccaes_arm_encrypt_key128(raw_key, expanded_key);
        return 0;
    case 24:
        sep_ccaes_arm_encrypt_key192(raw_key, expanded_key);
        return 0;
    case 32:
        sep_ccaes_arm_encrypt_key256(raw_key, expanded_key);
        return 0;
    default:
        return -1;
    }
}

int sep_ccaes_arm_decrypt_key(
    const void *mode,
    sep_aes_key_context_t *expanded_key,
    sep_size_t raw_key_length,
    const void *raw_key
) {
    const int result = sep_ccaes_arm_encrypt_key(
        mode,
        expanded_key,
        raw_key_length,
        raw_key
    );
    if (result == -1) {
        return result;
    }
    const sep_size_t round_count = expanded_key->final_round_offset / 16;
    for (sep_size_t round = 1; round < round_count; ++round) {
        aes_inverse_mix_columns(&expanded_key->round_keys[16 * round]);
    }
    return result;
}

int sep_ccaes_cbc_decrypt_key_with_length_check(
    const void *mode,
    sep_aes_key_context_t *key,
    sep_size_t raw_key_length,
    const void *raw_key
) {
    (void)mode;
    return aes_key_length_checked(key, raw_key_length, raw_key, 1);
}

int sep_ccaes_cbc_encrypt_key_with_length_check(
    const void *mode,
    sep_aes_key_context_t *key,
    sep_size_t raw_key_length,
    const void *raw_key
) {
    (void)mode;
    return aes_key_length_checked(key, raw_key_length, raw_key, 0);
}

int sep_ccaes_ecb_encrypt_key_with_length_check(
    const void *mode,
    sep_aes_key_context_t *key,
    sep_size_t raw_key_length,
    const void *raw_key
) {
    (void)mode;
    return aes_key_length_checked(key, raw_key_length, raw_key, 0);
}

int sep_acceleratecrypto_ecb_aes_encrypt(
    const sep_aes_key_context_t *key,
    sep_u32 block_count,
    const void *input,
    void *output
) {
    const sep_u8 *input_bytes = input;
    sep_u8 *output_bytes = output;
    for (sep_u32 block = 0; block < block_count; ++block) {
        sep_u8 source[16];
        aes_copy(source, input_bytes + 16 * block, 16);
        aes_encrypt_block(key, source, output_bytes + 16 * block);
    }
    return 0;
}

int sep_ccaes_arm_encrypt_ecb(
    const sep_aes_key_context_t *key,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    return sep_acceleratecrypto_ecb_aes_encrypt(
        key,
        (sep_u32)block_count,
        input,
        output
    );
}

int sep_ccaes_arm_encrypt_cbc(
    const sep_aes_key_context_t *key,
    void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    if (block_count == 0) {
        return (int)(uintptr_t)key;
    }
    if (key->final_round_offset != 160 && key->final_round_offset != 192 &&
        key->final_round_offset != 224) {
        return -1;
    }

    sep_u8 chain[16];
    aes_copy(chain, iv, 16);
    const sep_u8 *input_bytes = input;
    sep_u8 *output_bytes = output;
    for (sep_size_t block = 0; block < block_count; ++block) {
        sep_u8 source[16];
        aes_copy(source, input_bytes + 16 * block, 16);
        for (sep_size_t index = 0; index < 16; ++index) {
            source[index] ^= chain[index];
        }
        aes_encrypt_block(key, source, output_bytes + 16 * block);
        aes_copy(chain, output_bytes + 16 * block, 16);
    }
    aes_copy(iv, chain, 16);
    return 0;
}

int sep_ccaes_arm_decrypt_cbc(
    const sep_aes_key_context_t *key,
    void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
) {
    if (block_count == 0) {
        return (int)(uintptr_t)key;
    }
    if (key->final_round_offset != 160 && key->final_round_offset != 192 &&
        key->final_round_offset != 224) {
        return -1;
    }

    sep_u8 chain[16];
    aes_copy(chain, iv, 16);
    const sep_u8 *input_bytes = input;
    sep_u8 *output_bytes = output;
    for (sep_size_t block = 0; block < block_count; ++block) {
        sep_u8 ciphertext[16];
        sep_u8 plaintext[16];
        aes_copy(ciphertext, input_bytes + 16 * block, 16);
        aes_decrypt_block(key, ciphertext, plaintext);
        for (sep_size_t index = 0; index < 16; ++index) {
            output_bytes[16 * block + index] = plaintext[index] ^ chain[index];
        }
        aes_copy(chain, ciphertext, 16);
    }
    aes_copy(iv, chain, 16);
    return 0;
}

int sep_aes_cbc_decrypt(
    void *output,
    const void *input,
    sep_size_t length,
    const sep_u8 *key,
    sep_size_t key_bit_length,
    const sep_u8 iv[16]
) {
    if ((length & 15U) != 0) {
        __builtin_trap();
    }
    sep_aes_key_context_t expanded_key;
    sep_u8 mutable_iv[16];
    aes_copy(mutable_iv, iv, 16);
    const sep_size_t key_length = sep_aes_key_length_bytes(key_bit_length);
    if (sep_ccaes_cbc_decrypt_key_with_length_check(
        0,
        &expanded_key,
        key_length,
        key
    ) != 0) {
        return -1;
    }
    return sep_ccaes_arm_decrypt_cbc(
        &expanded_key,
        mutable_iv,
        length / 16,
        input,
        output
    ) == 0 ? 0 : -1;
}

sep_bool sep_aes_cbc_decrypt_checked(
    void *output,
    const void *input,
    sep_size_t length,
    const sep_u8 *key,
    sep_size_t key_bit_length,
    const sep_u8 iv[16]
) {
    return sep_aes_cbc_decrypt(
        output,
        input,
        length,
        key,
        key_bit_length,
        iv
    ) == 0;
}
