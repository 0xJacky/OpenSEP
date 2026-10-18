#include "open_secure_rom/crypto_digest.h"

#include "open_secure_rom/runtime.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected digest fatal path");
    __builtin_unreachable();
}

static sep_u8 hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return (sep_u8)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (sep_u8)(value - 'a' + 10);
    }
    assert(0 && "invalid hexadecimal digest");
    return 0;
}

static void assert_digest_hex(
    const sep_u8 *digest,
    sep_size_t digest_length,
    const char *expected_hex
) {
    for (sep_size_t index = 0; index < digest_length; ++index) {
        const sep_u8 expected = (sep_u8)(
            (hex_nibble(expected_hex[index * 2]) << 4) |
            hex_nibble(expected_hex[index * 2 + 1])
        );
        assert(digest[index] == expected);
    }
    assert(expected_hex[digest_length * 2] == '\0');
}

static void assert_one_shot(
    const sep_ccdigest_info_t *descriptor,
    const void *message,
    sep_size_t message_length,
    const char *expected_hex
) {
    sep_u8 digest[64];
    sep_memzero(digest, sizeof(digest));
    sep_ccdigest(descriptor, message_length, message, digest);
    assert_digest_hex(digest, descriptor->output_size, expected_hex);
}

static void assert_million_a(
    const sep_ccdigest_info_t *descriptor,
    const char *expected_hex
) {
    sep_u8 chunk[1000];
    sep_memset(chunk, 'a', sizeof(chunk));
    sep_ccdigest_ctx_t context;
    sep_memzero(&context, sizeof(context));
    sep_ccdigest_init(descriptor, &context);
    for (sep_size_t index = 0; index < 1000; ++index) {
        sep_ccdigest_update(descriptor, &context, sizeof(chunk), chunk);
    }
    sep_u8 digest[64];
    descriptor->final(descriptor, &context, digest);
    assert_digest_hex(digest, descriptor->output_size, expected_hex);
}

static void test_sha1(void) {
    const sep_ccdigest_info_t *descriptor =
        sep_digest_info_for_bit_length(160);
    assert(descriptor->output_size == 20);
    assert(descriptor->state_size == 20);
    assert(descriptor->block_size == 64);
    assert_one_shot(
        descriptor,
        "",
        0,
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    assert_one_shot(
        descriptor,
        "abc",
        3,
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_million_a(
        descriptor,
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    );
}

static void test_sha256(void) {
    const sep_ccdigest_info_t *descriptor = sep_ccsha256_di();
    assert(descriptor == sep_digest_info_for_bit_length(256));
    assert(descriptor->output_size == 32);
    assert(descriptor->state_size == 32);
    assert(descriptor->block_size == 64);
    assert_one_shot(
        descriptor,
        "",
        0,
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    );
    assert_one_shot(
        descriptor,
        "abc",
        3,
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    );
    assert_million_a(
        descriptor,
        "cdc76e5c9914fb9281a1c7e284d73e67"
        "f1809a48a497200e046d39ccc7112cd0"
    );

    sep_u8 digest[32];
    sep_digest_by_bit_length(256, "abc", 3, digest, sizeof(digest));
    assert_digest_hex(
        digest,
        sizeof(digest),
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    );
}

static void test_sha384(void) {
    const sep_ccdigest_info_t *descriptor =
        sep_digest_info_for_bit_length(384);
    assert(descriptor->output_size == 48);
    assert(descriptor->state_size == 64);
    assert(descriptor->block_size == 128);
    assert_one_shot(
        descriptor,
        "",
        0,
        "38b060a751ac96384cd9327eb1b1e36a"
        "21fdb71114be07434c0cc7bf63f6e1da"
        "274edebfe76f65fbd51ad2f14898b95b"
    );
    assert_one_shot(
        descriptor,
        "abc",
        3,
        "cb00753f45a35e8bb5a03d699ac65007"
        "272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7"
    );
    assert_million_a(
        descriptor,
        "9d0e1809716474cb086e834e310a4a1c"
        "ed149e9c00f248527972cec5704c2a5b"
        "07b8b3dc38ecc4ebae97ddd87f3d8985"
    );
}

static void test_sha512(void) {
    const sep_ccdigest_info_t *descriptor =
        open_secure_rom_sha512_di();
    assert(descriptor->output_size == 64);
    assert(descriptor->state_size == 64);
    assert(descriptor->block_size == 128);
    assert_one_shot(
        descriptor,
        "",
        0,
        "cf83e1357eefb8bdf1542850d66d8007"
        "d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e"
    );
    assert_one_shot(
        descriptor,
        "abc",
        3,
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_million_a(
        descriptor,
        "e718483d0ce769644e2e42c7bc15b463"
        "8e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31b"
        "eb009c5c2c49aa2e4eadb217ad8cc09b"
    );
}

static void test_keccak_f1600(void) {
    static const sep_u64 expected[25] = {
        0xf1258f7940e1dde7ULL, 0x84d5ccf933c0478aULL,
        0xd598261ea65aa9eeULL, 0xbd1547306f80494dULL,
        0x8b284e056253d057ULL, 0xff97a42d7f8e6fd4ULL,
        0x90fee5a0a44647c4ULL, 0x8c5bda0cd6192e76ULL,
        0xad30a6f71b19059cULL, 0x30935ab7d08ffc64ULL,
        0xeb5aa93f2317d635ULL, 0xa9a6e6260d712103ULL,
        0x81a57c16dbcf555fULL, 0x43b831cd0347c826ULL,
        0x01f22f1a11a5569fULL, 0x05e5635a21d9ae61ULL,
        0x64befef28cc970f2ULL, 0x613670957bc46611ULL,
        0xb87c5a554fd00ecbULL, 0x8c3ee88a1ccf32c8ULL,
        0x940c7922ae3a2614ULL, 0x1841f924a2c509e4ULL,
        0x16f53526e70465c2ULL, 0x75f644e97f30a13bULL,
        0xeaf1ff7b5ceca249ULL,
    };
    sep_u64 state[25] = {0};
    sep_cckeccak_f1600_c(state);
    for (sep_size_t index = 0; index < 25; ++index) {
        assert(state[index] == expected[index]);
    }
}

int main(void) {
    test_sha1();
    test_sha256();
    test_sha384();
    test_sha512();
    test_keccak_f1600();
}
