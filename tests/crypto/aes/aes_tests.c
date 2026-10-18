#include "open_secure_rom/aes.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void assert_bytes_equal(
    const sep_u8 *actual,
    const sep_u8 *expected,
    sep_size_t length
) {
    assert(memcmp(actual, expected, length) == 0);
}

static void test_ecb_known_answer_vectors(void) {
    const sep_u8 plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const sep_u8 key128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const sep_u8 expected128[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    };
    const sep_u8 key192[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const sep_u8 expected192[16] = {
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };
    const sep_u8 key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const sep_u8 expected256[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };

    sep_aes_key_context_t context;
    sep_u8 output[16];
    sep_ccaes_arm_encrypt_key128(key128, &context);
    assert(context.final_round_offset == 160);
    assert(sep_ccaes_arm_encrypt_ecb(&context, 1, plaintext, output) == 0);
    assert_bytes_equal(output, expected128, 16);

    sep_ccaes_arm_encrypt_key192(key192, &context);
    assert(context.final_round_offset == 192);
    assert(sep_acceleratecrypto_ecb_aes_encrypt(
        &context,
        1,
        plaintext,
        output
    ) == 0);
    assert_bytes_equal(output, expected192, 16);

    sep_ccaes_arm_encrypt_key256(key256, &context);
    assert(context.final_round_offset == 224);
    assert(sep_ccaes_arm_encrypt_ecb(&context, 1, plaintext, output) == 0);
    assert_bytes_equal(output, expected256, 16);

    sep_u8 zero_iv[16] = {0};
    assert(sep_ccaes_arm_decrypt_key(0, &context, 192, key192) == 0);
    assert(sep_ccaes_arm_decrypt_cbc(
        &context,
        zero_iv,
        1,
        expected192,
        output
    ) == 0);
    assert_bytes_equal(output, plaintext, 16);

    memset(zero_iv, 0, sizeof(zero_iv));
    assert(sep_ccaes_arm_decrypt_key(0, &context, 32, key256) == 0);
    assert(sep_ccaes_arm_decrypt_cbc(
        &context,
        zero_iv,
        1,
        expected256,
        output
    ) == 0);
    assert_bytes_equal(output, plaintext, 16);
}

static void test_cbc_known_answer_vectors(void) {
    const sep_u8 key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const sep_u8 original_iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const sep_u8 plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    const sep_u8 ciphertext[32] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    };

    sep_aes_key_context_t encrypt_key;
    sep_u8 iv[16];
    sep_u8 output[32];
    assert(sep_ccaes_cbc_encrypt_key_with_length_check(
        0,
        &encrypt_key,
        16,
        key
    ) == 0);
    memcpy(iv, original_iv, sizeof(iv));
    assert(sep_ccaes_arm_encrypt_cbc(
        &encrypt_key,
        iv,
        2,
        plaintext,
        output
    ) == 0);
    assert_bytes_equal(output, ciphertext, sizeof(output));
    assert_bytes_equal(iv, ciphertext + 16, 16);

    sep_aes_key_context_t decrypt_key;
    assert(sep_ccaes_cbc_decrypt_key_with_length_check(
        0,
        &decrypt_key,
        128,
        key
    ) == 0);
    memcpy(iv, original_iv, sizeof(iv));
    assert(sep_ccaes_arm_decrypt_cbc(
        &decrypt_key,
        iv,
        2,
        ciphertext,
        output
    ) == 0);
    assert_bytes_equal(output, plaintext, sizeof(output));
    assert_bytes_equal(iv, ciphertext + 16, 16);

    memcpy(output, ciphertext, sizeof(output));
    memcpy(iv, original_iv, sizeof(iv));
    assert(sep_ccaes_arm_decrypt_cbc(
        &decrypt_key,
        iv,
        2,
        output,
        output
    ) == 0);
    assert_bytes_equal(output, plaintext, sizeof(output));

    assert(sep_aes_cbc_decrypt_checked(
        output,
        ciphertext,
        sizeof(ciphertext),
        key,
        128,
        original_iv
    ) == 1);
    assert_bytes_equal(output, plaintext, sizeof(output));
}

static void test_key_length_and_mode_abis(void) {
    const sep_u8 key[32] = {0};
    sep_aes_key_context_t context;
    assert(sep_aes_key_length_bytes(128) == 16);
    assert(sep_aes_key_length_bytes(192) == 24);
    assert(sep_aes_key_length_bytes(256) == 32);
    assert(sep_ccaes_arm_encrypt_key(0, &context, 256, key) == 0);
    assert(context.final_round_offset == 224);
    assert(sep_ccaes_arm_encrypt_key(0, &context, 15, key) == -1);
    assert(sep_ccaes_ecb_encrypt_key_with_length_check(
        0,
        &context,
        15,
        key
    ) == -7);
    assert(sep_ccaes_cbc_encrypt_key_with_length_check(
        0,
        &context,
        129,
        key
    ) == -7);

    context.final_round_offset = 0;
    sep_u8 block[16] = {0};
    assert(sep_ccaes_arm_encrypt_cbc(&context, block, 1, block, block) == -1);
    assert(sep_ccaes_arm_decrypt_cbc(&context, block, 1, block, block) == -1);

    const sep_ccmode_cbc_t *cbc = sep_ccaes_cbc_encrypt_mode();
    const sep_ccmode_ecb_t *ecb = sep_ccaes_ecb_encrypt_mode();
    const sep_ccmode_ccm_t *ccm_encrypt = sep_ccaes_ccm_encrypt_mode();
    const sep_ccmode_ccm_t *ccm_decrypt = sep_ccaes_ccm_decrypt_mode();
    assert(cbc->size == sizeof(sep_aes_key_context_t));
    assert(cbc->block_size == 16);
    assert(cbc->init != 0 && cbc->cbc != 0);
    assert(ecb->size == sizeof(sep_aes_key_context_t));
    assert(ecb->block_size == 16);
    assert(ecb->init != 0 && ecb->ecb != 0);
    assert(ccm_encrypt->size == sizeof(sep_ccccm_ctx_t));
    assert(ccm_encrypt->nonce_size == sizeof(sep_ccccm_nonce_t));
    assert(ccm_encrypt->custom == ecb && ccm_encrypt->encrypt == 1);
    assert(ccm_decrypt->custom == ecb && ccm_decrypt->encrypt == 0);

    sep_ccmode_ccm_t descriptor_copy;
    memset(&descriptor_copy, 0xa5, sizeof(descriptor_copy));
    sep_ccmode_copy_ccm_descriptor(&descriptor_copy, ccm_encrypt);
    assert(memcmp(&descriptor_copy, ccm_encrypt, 81) == 0);
    for (sep_size_t index = 81; index < sizeof(descriptor_copy); ++index) {
        assert(((const sep_u8 *)&descriptor_copy)[index] == 0xa5);
    }
}

static void test_cbc_mode_wrappers(void) {
    const sep_u8 key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const sep_u8 iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const sep_u8 plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    const sep_u8 ciphertext[32] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    };

    const sep_ccmode_cbc_t *mode = sep_ccaes_cbc_encrypt_mode();
    sep_u8 output[32];
    assert(sep_cccbc_one_shot(
        mode,
        sizeof(key),
        key,
        iv,
        2,
        plaintext,
        output
    ) == 0);
    assert_bytes_equal(output, ciphertext, sizeof(output));

    sep_aes_key_context_t context;
    sep_u8 mutable_iv[16];
    assert(sep_cccbc_init_internal(
        mode,
        &context,
        sizeof(key),
        key
    ) == 0);
    assert(sep_cccbc_set_iv_internal(mode, mutable_iv, iv) == 0);
    assert(sep_cccbc_update_internal(
        mode,
        &context,
        mutable_iv,
        1,
        plaintext,
        output
    ) == 0);
    assert(sep_cccbc_update_internal(
        mode,
        &context,
        mutable_iv,
        1,
        plaintext + 16,
        output + 16
    ) == 0);
    assert_bytes_equal(output, ciphertext, sizeof(output));

    sep_u8 zero_iv_output[32];
    sep_u8 zero_iv[16] = {0};
    assert(sep_ccaes_arm_encrypt_cbc(
        &context,
        zero_iv,
        2,
        plaintext,
        zero_iv_output
    ) == 0);
    assert(sep_cccbc_one_shot(
        mode,
        sizeof(key),
        key,
        0,
        2,
        plaintext,
        output
    ) == 0);
    assert_bytes_equal(output, zero_iv_output, sizeof(output));

    assert(sep_cccbc_one_shot_explicit_internal(
        mode,
        sizeof(key),
        key,
        15,
        iv,
        2,
        plaintext,
        output
    ) == -7);

    sep_u8 zeros[16] = {0};
    assert(sep_cccbc_set_iv_internal(mode, mutable_iv, 0) == 0);
    assert_bytes_equal(mutable_iv, zeros, sizeof(zeros));
}

static void test_ccm_rfc3610_vector(void) {
    const sep_u8 key[16] = {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    };
    const sep_u8 nonce[13] = {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
    };
    const sep_u8 aad[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    const sep_u8 plaintext[23] = {
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    };
    const sep_u8 ciphertext[23] = {
        0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
        0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
        0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84,
    };
    const sep_u8 expected_tag[8] = {
        0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0,
    };

    sep_u8 output[23];
    sep_u8 tag[8];
    assert(sep_ccccm_one_shot(
        sep_ccaes_ccm_encrypt_mode(),
        sizeof(key),
        key,
        sizeof(nonce),
        nonce,
        sizeof(plaintext),
        plaintext,
        output,
        sizeof(aad),
        aad,
        sizeof(tag),
        tag
    ) == 0);
    assert_bytes_equal(output, ciphertext, sizeof(output));
    assert_bytes_equal(tag, expected_tag, sizeof(tag));

    sep_u8 recovered[23];
    sep_u8 decrypt_tag[8];
    assert(sep_ccccm_one_shot(
        sep_ccaes_ccm_decrypt_mode(),
        sizeof(key),
        key,
        sizeof(nonce),
        nonce,
        sizeof(ciphertext),
        ciphertext,
        recovered,
        sizeof(aad),
        aad,
        sizeof(decrypt_tag),
        decrypt_tag
    ) == 0);
    assert_bytes_equal(recovered, plaintext, sizeof(recovered));
    assert_bytes_equal(decrypt_tag, expected_tag, sizeof(decrypt_tag));
}

static void test_ccm_chunked_and_in_place(void) {
    const sep_u8 key[16] = {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    };
    const sep_u8 nonce[13] = {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
    };
    const sep_u8 aad[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    const sep_u8 plaintext[23] = {
        8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    };
    const sep_u8 ciphertext[23] = {
        0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
        0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
        0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84,
    };
    const sep_u8 expected_tag[8] = {
        0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0,
    };

    const sep_ccmode_ccm_t *encrypt_mode = sep_ccaes_ccm_encrypt_mode();
    sep_ccccm_ctx_t context;
    sep_ccccm_nonce_t nonce_context;
    sep_u8 buffer[23];
    sep_u8 tag[8];
    assert(encrypt_mode->init(encrypt_mode, &context, sizeof(key), key) == 0);
    assert(encrypt_mode->set_iv(
        &context,
        &nonce_context,
        sizeof(nonce),
        nonce,
        sizeof(tag),
        sizeof(aad),
        sizeof(plaintext)
    ) == 0);
    assert(encrypt_mode->cbcmac(&context, &nonce_context, 3, aad) == 0);
    assert(encrypt_mode->cbcmac(&context, &nonce_context, 5, aad + 3) == 0);
    assert(encrypt_mode->ccm(
        &context,
        &nonce_context,
        5,
        plaintext,
        buffer
    ) == 0);
    assert(encrypt_mode->ccm(
        &context,
        &nonce_context,
        11,
        plaintext + 5,
        buffer + 5
    ) == 0);
    assert(encrypt_mode->ccm(
        &context,
        &nonce_context,
        7,
        plaintext + 16,
        buffer + 16
    ) == 0);
    assert(encrypt_mode->finalize(&context, &nonce_context, tag) == 0);
    assert_bytes_equal(buffer, ciphertext, sizeof(buffer));
    assert_bytes_equal(tag, expected_tag, sizeof(tag));

    memcpy(buffer, plaintext, sizeof(buffer));
    assert(sep_ccccm_one_shot(
        encrypt_mode,
        sizeof(key),
        key,
        sizeof(nonce),
        nonce,
        sizeof(buffer),
        buffer,
        buffer,
        sizeof(aad),
        aad,
        sizeof(tag),
        tag
    ) == 0);
    assert_bytes_equal(buffer, ciphertext, sizeof(buffer));
    assert_bytes_equal(tag, expected_tag, sizeof(tag));

    assert(sep_ccccm_one_shot(
        sep_ccaes_ccm_decrypt_mode(),
        sizeof(key),
        key,
        sizeof(nonce),
        nonce,
        sizeof(buffer),
        buffer,
        buffer,
        sizeof(aad),
        aad,
        sizeof(tag),
        tag
    ) == 0);
    assert_bytes_equal(buffer, plaintext, sizeof(buffer));
    assert_bytes_equal(tag, expected_tag, sizeof(tag));

    assert(sep_ccmode_ccm_reset(&context, &nonce_context) == 0);
    assert(sep_ccmode_ccm_finalize(&context, &nonce_context, tag) == -68);
    assert(sep_ccmode_ccm_set_iv(
        &context,
        &nonce_context,
        6,
        nonce,
        8,
        0,
        0
    ) == -1);
}

typedef void (*ccm_block_function_t)(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
);

static void test_ccm_block_kernels(void) {
    const sep_u8 keys[3][32] = {
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        },
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        },
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        },
    };
    const sep_size_t key_lengths[3] = {16, 24, 32};
    const ccm_block_function_t encrypt_functions[3] = {
        sep_ccm128_encrypt,
        sep_ccm192_encrypt,
        sep_ccm256_encrypt,
    };
    const ccm_block_function_t decrypt_functions[3] = {
        sep_ccm128_decrypt,
        sep_ccm192_decrypt,
        sep_ccm256_decrypt,
    };
    const sep_u8 plaintext[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };

    for (sep_size_t index = 0; index < 3; ++index) {
        sep_aes_key_context_t key_context;
        assert(sep_ccaes_arm_encrypt_key(
            0,
            &key_context,
            key_lengths[index],
            keys[index]
        ) == 0);
        sep_u8 initial_counter[16] = {
            0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
            0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0x00, 0x00, 0x00,
        };
        sep_u8 initial_tag[16] = {
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
        };
        sep_u8 encrypt_counter[16];
        sep_u8 decrypt_counter[16];
        sep_u8 encrypt_tag[16];
        sep_u8 decrypt_tag[16];
        sep_u8 ciphertext[32];
        sep_u8 recovered[32];
        memcpy(encrypt_counter, initial_counter, 16);
        memcpy(decrypt_counter, initial_counter, 16);
        memcpy(encrypt_tag, initial_tag, 16);
        memcpy(decrypt_tag, initial_tag, 16);

        encrypt_functions[index](
            plaintext,
            ciphertext,
            encrypt_tag,
            2,
            &key_context,
            encrypt_counter,
            3
        );
        decrypt_functions[index](
            ciphertext,
            recovered,
            decrypt_tag,
            2,
            &key_context,
            decrypt_counter,
            3
        );
        assert_bytes_equal(recovered, plaintext, sizeof(recovered));
        assert_bytes_equal(decrypt_tag, encrypt_tag, sizeof(encrypt_tag));
        assert_bytes_equal(
            decrypt_counter,
            encrypt_counter,
            sizeof(encrypt_counter)
        );

        memcpy(ciphertext, plaintext, sizeof(ciphertext));
        memcpy(encrypt_counter, initial_counter, 16);
        memcpy(encrypt_tag, initial_tag, 16);
        encrypt_functions[index](
            ciphertext,
            ciphertext,
            encrypt_tag,
            2,
            &key_context,
            encrypt_counter,
            3
        );
        assert(memcmp(ciphertext, plaintext, sizeof(ciphertext)) != 0);
    }
}

int main(void) {
    test_ecb_known_answer_vectors();
    test_cbc_known_answer_vectors();
    test_key_length_and_mode_abis();
    test_cbc_mode_wrappers();
    test_ccm_rfc3610_vector();
    test_ccm_chunked_and_in_place();
    test_ccm_block_kernels();
}
