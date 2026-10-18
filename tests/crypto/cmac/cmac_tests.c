#include "open_secure_rom/cmac.h"

#include <assert.h>
#include <string.h>

enum {
    AES_CMAC_CONTEXT_SIZE = 340,
};

typedef union cmac_test_context {
    sep_u64 alignment;
    sep_u8 bytes[AES_CMAC_CONTEXT_SIZE];
} cmac_test_context_t;

static sep_cccmac_ctx_t *test_context(cmac_test_context_t *storage) {
    return (sep_cccmac_ctx_t *)storage->bytes;
}

static void assert_bytes_equal(
    const void *actual,
    const void *expected,
    sep_size_t length
) {
    assert(memcmp(actual, expected, length) == 0);
}

static void test_cmac_sp800_38b_vectors(void) {
    const sep_u8 key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const sep_u8 message[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const sep_u8 expected[4][16] = {
        {
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
            0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
        },
        {
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
        },
        {
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
            0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
        },
        {
            0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
            0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
        },
    };
    const sep_size_t lengths[4] = {0, 16, 40, 64};
    const sep_ccmode_cbc_t *cbc = sep_ccaes_cbc_encrypt_mode();

    for (sep_size_t index = 0; index < 4; ++index) {
        cmac_test_context_t storage;
        sep_u8 mac[16];
        memset(&storage, 0, sizeof(storage));
        assert(sep_cccmac_init(
            cbc,
            test_context(&storage),
            sizeof(key),
            key
        ) == 0);
        assert(sep_cccmac_update(
            test_context(&storage),
            lengths[index],
            message
        ) == 0);
        assert(sep_cccmac_final_generate(
            test_context(&storage),
            sizeof(mac),
            mac
        ) == 0);
        assert_bytes_equal(mac, expected[index], sizeof(mac));
    }
}

static void test_cmac_streaming_and_verify(void) {
    const sep_u8 key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const sep_u8 message[40] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    const sep_u8 expected[16] = {
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
    };
    const sep_ccmode_cbc_t *cbc = sep_ccaes_cbc_encrypt_mode();
    cmac_test_context_t storage;
    sep_u8 mac[16];
    const sep_u8 expected_subkey1[16] = {
        0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66,
        0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde,
    };
    const sep_u8 expected_subkey2[16] = {
        0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc,
        0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b,
    };
    sep_u8 subkey1[16];
    sep_u8 subkey2[16];
    assert(sep_cccmac_generate_subkeys(
        cbc,
        sizeof(key),
        key,
        subkey1,
        subkey2
    ) == 0);
    assert_bytes_equal(subkey1, expected_subkey1, sizeof(subkey1));
    assert_bytes_equal(subkey2, expected_subkey2, sizeof(subkey2));

    memset(&storage, 0, sizeof(storage));
    assert(sep_cccmac_init_internal(
        cbc,
        test_context(&storage),
        sizeof(key),
        key
    ) == 0);
    assert(sep_cccmac_update_internal(test_context(&storage), 1, message) == 0);
    assert(sep_cccmac_update_internal(
        test_context(&storage),
        15,
        message + 1
    ) == 0);
    assert(sep_cccmac_update_internal(
        test_context(&storage),
        7,
        message + 16
    ) == 0);
    assert(sep_cccmac_update_internal(
        test_context(&storage),
        17,
        message + 23
    ) == 0);
    assert(sep_cccmac_final_generate_internal(
        test_context(&storage),
        sizeof(mac),
        mac
    ) == 0);
    assert_bytes_equal(mac, expected, sizeof(mac));

    memset(&storage, 0, sizeof(storage));
    assert(sep_cccmac_init(cbc, test_context(&storage), sizeof(key), key) == 0);
    assert(sep_cccmac_update(test_context(&storage), sizeof(message), message) == 0);
    assert(sep_cccmac_final_verify(
        test_context(&storage),
        sizeof(expected),
        expected
    ) == 0);

    sep_u8 incorrect[16];
    memcpy(incorrect, expected, sizeof(incorrect));
    incorrect[15] ^= 1;
    memset(&storage, 0, sizeof(storage));
    assert(sep_cccmac_init(cbc, test_context(&storage), sizeof(key), key) == 0);
    assert(sep_cccmac_update(test_context(&storage), sizeof(message), message) == 0);
    assert(sep_cccmac_final_verify_internal(
        test_context(&storage),
        sizeof(incorrect),
        incorrect
    ) == -5);

    memset(&storage, 0, sizeof(storage));
    assert(sep_cccmac_init(cbc, test_context(&storage), sizeof(key), key) == 0);
    assert(sep_cccmac_update(test_context(&storage), sizeof(message), message) == 0);
    assert(sep_cccmac_final_generate(test_context(&storage), 8, mac) == 0);
    assert_bytes_equal(mac, expected, 8);
    assert(sep_cccmac_init(cbc, test_context(&storage), 15, key) == -7);

    memset(&storage, 0, sizeof(storage));
    assert(sep_cccmac_init(cbc, test_context(&storage), sizeof(key), key) == 0);
    assert(sep_cccmac_final_generate(test_context(&storage), 0, mac) == -1);
}

static void test_kdf_sp800_108_vectors(void) {
    const sep_u8 key128[16] = {
        0xc1, 0x0b, 0x15, 0x2e, 0x8c, 0x97, 0xb7, 0x7e,
        0x18, 0x70, 0x4e, 0x0f, 0x0b, 0xd3, 0x83, 0x05,
    };
    const sep_u8 fixed128[60] = {
        0x98, 0xcd, 0x4c, 0xbb, 0xbe, 0xbe, 0x15, 0xd1,
        0x7d, 0xc8, 0x6e, 0x6d, 0xba, 0xd8, 0x00, 0xa2,
        0xdc, 0xbd, 0x64, 0xf7, 0xc7, 0xad, 0x0e, 0x78,
        0xe9, 0xcf, 0x94, 0xff, 0xdb, 0xa8, 0x9d, 0x03,
        0xe9, 0x7e, 0xad, 0xf6, 0xc4, 0xf7, 0xb8, 0x06,
        0xca, 0xf5, 0x2a, 0xa3, 0x8f, 0x09, 0xd0, 0xeb,
        0x71, 0xd7, 0x1f, 0x49, 0x7b, 0xcc, 0x69, 0x06,
        0xb4, 0x8d, 0x36, 0xc4,
    };
    const sep_u8 expected128[16] = {
        0x26, 0xfa, 0xf6, 0x19, 0x08, 0xad, 0x9e, 0xe8,
        0x81, 0xb8, 0x30, 0x5c, 0x22, 0x1d, 0xb5, 0x3f,
    };
    const sep_u8 key256[32] = {
        0x4d, 0x71, 0x92, 0x32, 0x80, 0xfb, 0x4a, 0x11,
        0xb2, 0x5f, 0x9d, 0x58, 0xd6, 0x77, 0x04, 0xd8,
        0xf8, 0xbb, 0x2d, 0x64, 0xd8, 0x9e, 0xdb, 0x9e,
        0xe6, 0xf3, 0xde, 0x32, 0xe4, 0x60, 0x1e, 0xfc,
    };
    const sep_u8 fixed256[60] = {
        0xe2, 0x7b, 0x8f, 0x35, 0x0b, 0xc1, 0x36, 0x0d,
        0xdc, 0x47, 0x6c, 0xb0, 0xca, 0xe8, 0x86, 0xf0,
        0x16, 0x1d, 0xa2, 0x2e, 0xe8, 0x15, 0x9c, 0x33,
        0x0f, 0x54, 0x5a, 0xf1, 0xd7, 0x82, 0xa0, 0xf0,
        0xaa, 0xcc, 0x3c, 0x3d, 0xe6, 0x21, 0x58, 0x07,
        0x16, 0x1d, 0xf0, 0x93, 0x36, 0xd4, 0x70, 0xb5,
        0xb4, 0xdb, 0x1c, 0xc0, 0xce, 0x73, 0xed, 0x1d,
        0x3e, 0xa2, 0x43, 0x80,
    };
    const sep_u8 expected256[32] = {
        0xb5, 0xb2, 0xbb, 0x67, 0x5f, 0xe7, 0xb0, 0x4a,
        0x52, 0x34, 0x0b, 0xd5, 0xcf, 0x24, 0x8d, 0x52,
        0x58, 0xa1, 0xf8, 0x37, 0xda, 0xd7, 0x47, 0xee,
        0x8a, 0x4e, 0x90, 0x46, 0x08, 0xa8, 0x97, 0x7d,
    };
    const sep_ccmode_cbc_t *cbc = sep_ccaes_cbc_encrypt_mode();
    sep_u8 output[32];

    assert(sep_ccnistkdf_ctr_cmac_fixed(
        cbc,
        32,
        sizeof(key128),
        key128,
        sizeof(fixed128),
        fixed128,
        sizeof(expected128),
        output
    ) == 0);
    assert_bytes_equal(output, expected128, sizeof(expected128));

    cmac_test_context_t storage;
    memset(&storage, 0, sizeof(storage));
    assert(sep_cccmac_init(
        cbc,
        test_context(&storage),
        sizeof(key128),
        key128
    ) == 0);
    sep_ccnistkdf_ctr_cmac_prf_eval(
        test_context(&storage),
        32,
        1,
        sizeof(fixed128),
        fixed128,
        output
    );
    assert_bytes_equal(output, expected128, sizeof(expected128));

    assert(sep_ccnistkdf_ctr_cmac_fixed_internal(
        cbc,
        24,
        sizeof(key256),
        key256,
        sizeof(fixed256),
        fixed256,
        sizeof(expected256),
        output
    ) == 0);
    assert_bytes_equal(output, expected256, sizeof(expected256));

    assert(sep_ccnistkdf_ctr_cmac_fixed(
        cbc,
        24,
        sizeof(key256),
        key256,
        sizeof(fixed256),
        fixed256,
        25,
        output
    ) == 0);
    assert_bytes_equal(output, expected256, 25);
    assert(sep_ccnistkdf_ctr_cmac_fixed(
        cbc,
        7,
        sizeof(key128),
        key128,
        sizeof(fixed128),
        fixed128,
        sizeof(expected128),
        output
    ) == -7);
    assert(sep_ccnistkdf_ctr_cmac_fixed(
        cbc,
        32,
        sizeof(key128),
        key128,
        sizeof(fixed128),
        fixed128,
        0,
        output
    ) == -7);
}

int main(void) {
    test_cmac_sp800_38b_vectors();
    test_cmac_streaming_and_verify();
    test_kdf_sp800_108_vectors();
}
