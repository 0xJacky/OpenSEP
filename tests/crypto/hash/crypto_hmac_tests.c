#include "open_secure_rom/crypto_hmac.h"

#include "open_secure_rom/runtime.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected HMAC fatal path");
    __builtin_unreachable();
}

static sep_u8 hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return (sep_u8)(value - '0');
    }
    return (sep_u8)(value - 'a' + 10);
}

static void assert_hex(
    const sep_u8 *bytes,
    sep_size_t length,
    const char *expected
) {
    for (sep_size_t index = 0; index < length; ++index) {
        const sep_u8 value = (sep_u8)(
            (hex_nibble(expected[index * 2]) << 4) |
            hex_nibble(expected[index * 2 + 1])
        );
        assert(bytes[index] == value);
    }
    assert(expected[length * 2] == '\0');
}

static void test_hmac_sha256(void) {
    sep_u8 key[20];
    sep_memset(key, 0x0b, sizeof(key));
    sep_u8 mac[32];
    sep_cchmac(
        sep_ccsha256_di(),
        sizeof(key),
        key,
        8,
        "Hi There",
        mac
    );
    assert_hex(
        mac,
        sizeof(mac),
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    );

    sep_cchmac_ctx_t context;
    sep_cchmac_init(sep_ccsha256_di(), &context, 4, "Jefe");
    sep_cchmac_update(sep_ccsha256_di(), &context, 10, "what do ya");
    sep_cchmac_update(
        sep_ccsha256_di(),
        &context,
        18,
        " want for nothing?"
    );
    sep_cchmac_final(sep_ccsha256_di(), &context, mac);
    assert_hex(
        mac,
        sizeof(mac),
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843"
    );
}

static void test_hkdf_sha256(void) {
    sep_u8 ikm[22];
    sep_memset(ikm, 0x0b, sizeof(ikm));
    static const sep_u8 salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    };
    static const sep_u8 info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
        0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };
    sep_u8 output[42];
    assert(sep_hkdf_by_bit_length(
        256,
        sizeof(ikm),
        ikm,
        sizeof(salt),
        salt,
        sizeof(info),
        info,
        sizeof(output),
        output
    ) == 0);
    assert_hex(
        output,
        sizeof(output),
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    );
}

static void test_checked_helpers(void) {
    sep_u8 key[32];
    sep_memset(key, 0x11, sizeof(key));
    const sep_checked_bytes32_t checked =
        sep_checked_bytes32_hmac_sha256("message", 7, key, sizeof(key));
    assert(checked.initialized == 1);
    assert(sep_hmac_sha256_tag_matches(
        key,
        "message",
        7,
        checked.bytes,
        sizeof(checked.bytes)
    ));
    sep_u8 different_tag[32];
    sep_memmove(different_tag, checked.bytes, sizeof(different_tag));
    different_tag[15] ^= 1;
    assert(!sep_hmac_sha256_tag_matches(
        key,
        "message",
        7,
        different_tag,
        16
    ));
}

int main(void) {
    test_hmac_sha256();
    test_hkdf_sha256();
    test_checked_helpers();
}
