#include "open_secure_rom/crypto_digest.h"
#include "open_secure_rom/rsa.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

enum {
    RSA2048_LIMBS = 32,
    RSA2048_CONTEXT_SIZE = SEP_CCRSA_PUB_CONTEXT_SIZE(RSA2048_LIMBS),
};

typedef union rsa_test_key_storage {
    sep_u64 alignment;
    sep_u8 bytes[RSA2048_CONTEXT_SIZE];
} rsa_test_key_storage_t;

typedef struct rsa_kat {
    sep_size_t digest_bits;
    const char *modulus;
    const char *exponent;
    const char *message;
    const char *signature;
} rsa_kat_t;

/* NIST CAVP FIPS 186-3 SigVer15_186-3, 2048-bit passing records. */
static const rsa_kat_t rsa_kats[] = {
    {
        256,
        "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026"
        "bcb2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae85208"
        "7d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d1"
        "1542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671de8"
        "74bb9cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f212b188"
        "81d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189ff968b9"
        "2f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce98f54ed23"
        "7b4a04a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb",
        "49d2a1",
        "95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad75"
        "6fbd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad3"
        "0b3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af59082"
        "4ca98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea",
        "51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027"
        "d39365de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656a"
        "fc196858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd5"
        "09e896f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d934129"
        "5d2f8e1cc4969bf228c860e07a3546be2eeda1cde48ee94d062801fe666e4a7ae"
        "8cb9cd79262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a5e5c"
        "c9e8546a221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048bc9ef9"
        "15bda25160729b508667ada84a0c27e7e26cf2abca413e5e4693f4a9405",
    },
    {
        384,
        "c858aea188541c0dd2626eec9a8c98511ca03870353128c1687d94a1be762a49"
        "40fca789831a720e108f2f7c1fc20aab38336b5668205d62963c51aad74757183"
        "faae7c0c59b9f679e96393e7f93e8a30ce99fed1b8e85e7146bd69a3f8dc5734"
        "bbacd51359f4f66aa507fbf4e69708877f7cd7cfb6868006e330869d9eee99f46"
        "6962b0dee9080d9413bdec2e41445190394a49ecb191167350be411cdd6ade4eb"
        "38c4c4bf891b43c91b5981a3bcc8a66f85e5cbaef751e3cbe94c7f193fd78ac5"
        "5048800250d5cc9e41b89319ac3d0258aa640299e165b0cf7e5e108f76a12f721"
        "32f6a2a4c239df0544d3d8407b94f9f38e9156c825a7eae001543fb264eb",
        "2a26db",
        "d6a169031049b0b3b582d22bf40b9fca45d2618457146c2b4ac6f6ed1f34291"
        "f6de8773955cd2e21b7944caca65794621a7ce181e5ddbb45e9252867877dc4e3"
        "5b6914ff26ec18890bf31f60fff1df367bc6c59373e58a1d8cb607188a394a290"
        "7ede95f6bf096731867f44fe520aacece76b5c3ea75023c9d3f3c080eaee376",
        "b9794f252e6907dc4c41de42ea5a0e6361114ac3814c4a92583ca70fd78e981"
        "90a0d9215bd5282e8520422093eff2e1cfa335cffcdcc27fe9bafe4516e74445d"
        "4aa17a08db754fc69b156d86ff26eb9e814f605142a3051d2fa64305d3e5c5c5f6"
        "7c7d9e38c5054d069c14b23e4278fa5a73381f61f90a9ec428c883f1366e27ec"
        "0219db8c942582a284c161eead307285d0e4df6b0d7dea0e8216d7ef2e4b2ede"
        "2296e0b780e5a3f8d15f123f737b9d6170074f758de32b6f1e958b27e422b053"
        "df8f5fbbbafbc14119260f7022cd2934e8faeffbd7085aabc44497bfe07387bc0"
        "e5aa02399eab99318adb98f99a677aa0683e0c11d638cb13907fc5c3147e5",
    },
};

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    abort();
}

static sep_u8 hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return (sep_u8)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (sep_u8)(value - 'a' + 10);
    }
    assert(0);
    return 0;
}

static sep_size_t decode_hex(const char *hex, sep_u8 *output) {
    const sep_size_t length = strlen(hex);
    assert((length & 1U) == 0);
    for (sep_size_t index = 0; index < length / 2; ++index) {
        output[index] = (sep_u8)(
            (hex_nibble(hex[2 * index]) << 4) |
            hex_nibble(hex[2 * index + 1])
        );
    }
    return length / 2;
}

static sep_ccrsa_pub_ctx_t *new_key(rsa_test_key_storage_t *storage) {
    memset(storage, 0, sizeof(*storage));
    sep_ccrsa_pub_ctx_t *key = (sep_ccrsa_pub_ctx_t *)storage->bytes;
    key->modulus_field.n = RSA2048_LIMBS;
    return key;
}

static sep_size_t encode_length(sep_u8 *output, sep_size_t length) {
    if (length < 0x80) {
        output[0] = (sep_u8)length;
        return 1;
    }
    if (length <= 0xff) {
        output[0] = 0x81;
        output[1] = (sep_u8)length;
        return 2;
    }
    output[0] = 0x82;
    output[1] = (sep_u8)(length >> 8);
    output[2] = (sep_u8)length;
    return 3;
}

static sep_size_t encode_integer(
    sep_u8 *output,
    const sep_u8 *integer,
    sep_size_t integer_length
) {
    const sep_bool needs_zero = (integer[0] & 0x80U) != 0;
    output[0] = 0x02;
    const sep_size_t length_size = encode_length(
        output + 1,
        integer_length + needs_zero
    );
    sep_size_t cursor = 1 + length_size;
    if (needs_zero) {
        output[cursor++] = 0;
    }
    memcpy(output + cursor, integer, integer_length);
    return cursor + integer_length;
}

static sep_size_t encode_public_key(
    sep_u8 output[270],
    const sep_u8 modulus[256],
    const sep_u8 *exponent,
    sep_size_t exponent_length
) {
    sep_u8 content[266];
    sep_size_t content_length = encode_integer(content, modulus, 256);
    content_length += encode_integer(
        content + content_length,
        exponent,
        exponent_length
    );
    output[0] = 0x30;
    const sep_size_t length_size = encode_length(output + 1, content_length);
    memcpy(output + 1 + length_size, content, content_length);
    return 1 + length_size + content_length;
}

static void assert_canary(const sep_u8 canary[16]) {
    static const sep_u8 expected[16] = {
        0xea, 0xc5, 0x4a, 0x7c, 0x9f, 0x28, 0xdf, 0x10,
        0xb6, 0xe9, 0x3e, 0xb9, 0x1c, 0xd3, 0x3a, 0xc5,
    };
    assert(memcmp(canary, expected, sizeof(expected)) == 0);
}

static void test_nist_sigver_vectors(void) {
    for (sep_size_t index = 0;
         index < sizeof(rsa_kats) / sizeof(rsa_kats[0]);
         ++index) {
        const rsa_kat_t *kat = &rsa_kats[index];
        sep_u8 modulus[256];
        sep_u8 exponent[8];
        sep_u8 message[128];
        sep_u8 signature[256];
        sep_u8 digest[48];
        sep_u8 canary[16];
        const sep_size_t exponent_length = decode_hex(kat->exponent, exponent);
        assert(decode_hex(kat->modulus, modulus) == sizeof(modulus));
        assert(decode_hex(kat->message, message) == sizeof(message));
        assert(decode_hex(kat->signature, signature) == sizeof(signature));

        rsa_test_key_storage_t storage;
        sep_ccrsa_pub_ctx_t *key = new_key(&storage);
        assert(sep_rsa_public_key_set_components(
            key,
            sizeof(modulus),
            modulus,
            exponent_length,
            exponent
        ) == 0);
        assert(key->modulus_field.n == RSA2048_LIMBS);
        assert(key->modulus_field.bitlen == 2048);

        const sep_ccdigest_info_t *digest_info =
            sep_digest_info_for_bit_length(kat->digest_bits);
        sep_ccdigest(digest_info, sizeof(message), message, digest);
        assert(sep_rsa_verify_pkcs1v15_digest_checked(
            key,
            digest_info->oid,
            digest_info->output_size,
            digest,
            sizeof(signature),
            signature,
            canary
        ) == 0);
        assert_canary(canary);

        signature[127] ^= 0x40;
        assert(sep_ccrsa_verify_pkcs1v15_digest(
            key,
            digest_info->oid,
            digest_info->output_size,
            digest,
            sizeof(signature),
            signature,
            canary
        ) == -146);
        assert(sep_ccrsa_verify_pkcs1v15_digest(
            key,
            digest_info->oid,
            digest_info->output_size,
            digest,
            sizeof(signature) - 1,
            signature,
            canary
        ) == -23);
    }
}

static void test_pkcs1_der(void) {
    const rsa_kat_t *kat = &rsa_kats[0];
    sep_u8 modulus[256];
    sep_u8 exponent[8];
    const sep_size_t exponent_length = decode_hex(kat->exponent, exponent);
    assert(decode_hex(kat->modulus, modulus) == sizeof(modulus));

    sep_u8 der[271];
    const sep_size_t der_length = encode_public_key(
        der,
        modulus,
        exponent,
        exponent_length
    );
    assert(der_length == 270);

    rsa_test_key_storage_t storage;
    sep_ccrsa_pub_ctx_t *key = new_key(&storage);
    assert(sep_rsa_public_key_decode_pkcs1(key, der_length, der) == 0);
    assert(key->modulus_field.bitlen == 2048);

    key = new_key(&storage);
    assert(sep_rsa_public_key_decode_pkcs1(key, der_length - 1, der) == -1);
    der[der_length] = 0;
    key = new_key(&storage);
    assert(sep_rsa_public_key_decode_pkcs1(key, der_length + 1, der) == 0);

    const sep_u8 wrong_tag[] = {
        0x30, 0x06, 0x04, 0x01, 0x7f, 0x02, 0x01, 0x03,
    };
    key = new_key(&storage);
    assert(sep_rsa_public_key_decode_pkcs1(
        key,
        sizeof(wrong_tag),
        wrong_tag
    ) == -1);

    const sep_u8 extra_integer[] = {
        0x30, 0x09, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x03,
        0x02, 0x01, 0x01,
    };
    key = new_key(&storage);
    assert(sep_rsa_public_key_decode_pkcs1(
        key,
        sizeof(extra_integer),
        extra_integer
    ) == -1);

    key = new_key(&storage);
    key->modulus_field.n = RSA2048_LIMBS - 1;
    assert(sep_rsa_public_key_set_components(
        key,
        sizeof(modulus),
        modulus,
        exponent_length,
        exponent
    ) == -1);
}

static void test_emsa_parser(void) {
    static const sep_u8 sha256_oid[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01,
    };
    sep_u8 digest[32];
    for (sep_size_t index = 0; index < sizeof(digest); ++index) {
        digest[index] = (sep_u8)index;
    }
    sep_u8 encoded[128];
    memset(encoded, 0xff, sizeof(encoded));
    encoded[0] = 0;
    encoded[1] = 1;
    const sep_size_t digest_info_length = sizeof(digest) + 19;
    sep_u8 *cursor = encoded + sizeof(encoded) - digest_info_length - 1;
    *cursor++ = 0;
    *cursor++ = 0x30;
    *cursor++ = (sep_u8)(digest_info_length - 2);
    *cursor++ = 0x30;
    *cursor++ = 13;
    memcpy(cursor, sha256_oid, sizeof(sha256_oid));
    cursor += sizeof(sha256_oid);
    *cursor++ = 0x05;
    *cursor++ = 0;
    *cursor++ = 0x04;
    *cursor++ = sizeof(digest);
    memcpy(cursor, digest, sizeof(digest));

    sep_u8 canary[16];
    assert(sep_ccrsa_emsa_pkcs1v15_verify_canary_out(
        sizeof(encoded),
        encoded,
        sizeof(digest),
        digest,
        sha256_oid,
        canary
    ) == 0);
    assert_canary(canary);
    encoded[2] = 0xfe;
    assert(sep_ccrsa_emsa_pkcs1v15_verify_canary_out(
        sizeof(encoded),
        encoded,
        sizeof(digest),
        digest,
        sha256_oid,
        canary
    ) != 0);
    assert(sep_ccrsa_emsa_pkcs1v15_verify_canary_out(
        61,
        encoded,
        sizeof(digest),
        digest,
        sha256_oid,
        canary
    ) == -23);
}

int main(void) {
    test_nist_sigver_vectors();
    test_pkcs1_der();
    test_emsa_parser();
}
