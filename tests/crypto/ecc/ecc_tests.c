#include "open_secure_rom/ecc.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct deterministic_rng {
    sep_ccrng_generate_fn generate;
    sep_u64 scalar[6];
} deterministic_rng_t;

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    abort();
}

static unsigned hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return (unsigned)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (unsigned)(value - 'a' + 10);
    }
    return (unsigned)(value - 'A' + 10);
}

static void decode_hex(const char *hex, sep_u8 *output, sep_size_t length) {
    assert(strlen(hex) == 2 * length);
    for (sep_size_t i = 0; i < length; ++i) {
        output[i] = (sep_u8)((hex_nibble(hex[2 * i]) << 4) |
                             hex_nibble(hex[2 * i + 1]));
    }
}

static void scalar_from_hex(const char *hex, sep_u64 scalar[6]) {
    sep_u8 bytes[48] = { 0 };
    const sep_size_t digits = strlen(hex);
    const sep_size_t bytes_used = (digits + 1) / 2;
    char padded[97];
    memset(padded, '0', sizeof(padded));
    padded[96] = '\0';
    memcpy(padded + 96 - digits, hex, digits);
    decode_hex(padded, bytes, 48);
    assert(bytes_used <= 48);
    assert(sep_ccn_read_uint_public_value(6, scalar, 48, bytes) == 0);
}

static void point_from_hex(
    const char *x,
    const char *y,
    sep_ccec_affine_point_t *point
) {
    sep_u8 bytes[48];
    decode_hex(x, bytes, sizeof(bytes));
    assert(sep_ccn_read_uint_public_value(6, point->xyz, 48, bytes) == 0);
    decode_hex(y, bytes, sizeof(bytes));
    assert(sep_ccn_read_uint_public_value(6, point->xyz + 6, 48, bytes) == 0);
}

static void encode_uncompressed(
    const sep_ccec_affine_point_t *point,
    sep_u8 output[97]
) {
    output[0] = 4;
    sep_ccn_write_uint_public_value(6, point->xyz, 48, output + 1);
    sep_ccn_write_uint_public_value(6, point->xyz + 6, 48, output + 49);
}

static int deterministic_generate(
    sep_ccrng_state_t *rng,
    sep_size_t output_length,
    void *output
) {
    deterministic_rng_t *state = (deterministic_rng_t *)(void *)rng;
    assert(output_length == 48);
    memcpy(output, state->scalar, output_length);
    return 0;
}

static sep_ccec_projective_point_t *projective(sep_u64 words[18]) {
    return (sep_ccec_projective_point_t *)(void *)words;
}

static sep_ccec_affine_point_t *affine(sep_u64 words[12]) {
    return (sep_ccec_affine_point_t *)(void *)words;
}

static void assert_affine_equal(
    const sep_ccec_affine_point_t *left,
    const sep_ccec_affine_point_t *right
) {
    assert(memcmp(left->xyz, right->xyz, 12 * sizeof(sep_u64)) == 0);
}

static void test_curve_and_point_kats(void) {
    const sep_ccec_cp_t *cp = sep_ccec_cp_384();
    assert(cp == sep_ccec_cp_384_asm());
    assert(cp->n == 6);
    assert(cp->bitlen == 384);
    assert(sep_ccec_compressed_x962_export_pub_size(cp) == 49);

    sep_u64 generator_words[12];
    sep_ccec_affine_point_t *generator = affine(generator_words);
    point_from_hex(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        generator
    );
    sep_u64 point_words[18];
    sep_ccec_projective_point_t *g = projective(point_words);
    assert(sep_ccec_validate_point_and_projectify_ws(
        NULL,
        cp,
        g,
        generator,
        NULL
    ) == 0);
    assert(sep_ccec_is_point_ws(NULL, cp, g));
    assert(!sep_ccec_is_point_at_infinity(cp, g));

    sep_u64 affine_words[12];
    sep_ccec_affine_point_t *roundtrip = affine(affine_words);
    assert(sep_ccec_affinify_ws(NULL, cp, roundtrip, g) == 0);
    assert_affine_equal(roundtrip, generator);

    sep_u64 doubled_words[18];
    sep_ccec_projective_point_t *doubled = projective(doubled_words);
    sep_ccec_double_ws(NULL, cp, doubled, g);
    assert(sep_ccec_affinify_ws(NULL, cp, roundtrip, doubled) == 0);
    sep_u64 expected_words[12];
    sep_ccec_affine_point_t *expected = affine(expected_words);
    point_from_hex(
        "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61",
        "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80",
        expected
    );
    assert_affine_equal(roundtrip, expected);

    sep_u64 scalar[6] = { 2, 0, 0, 0, 0, 0 };
    sep_u64 multiplied_words[18];
    sep_ccec_projective_point_t *multiplied = projective(multiplied_words);
    assert(sep_ccec_mult_ws(NULL, cp, multiplied, scalar, 2, g) == 0);
    assert(sep_ccec_affinify_ws(NULL, cp, roundtrip, multiplied) == 0);
    assert_affine_equal(roundtrip, expected);

    sep_u64 added_words[18];
    sep_ccec_projective_point_t *added = projective(added_words);
    sep_ccec_full_add_ws(NULL, cp, added, g, g);
    assert(sep_ccec_affinify_ws(NULL, cp, roundtrip, added) == 0);
    assert_affine_equal(roundtrip, expected);
}

static void test_import_and_invalid_inputs(void) {
    const sep_ccec_cp_t *cp = sep_ccec_cp_384();
    sep_u64 generator_words[12];
    sep_ccec_affine_point_t *generator = affine(generator_words);
    point_from_hex(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        generator
    );
    sep_u8 encoded[97];
    encode_uncompressed(generator, encoded);
    sep_u8 key_storage[SEP_CCEC_PUB_CTX_BYTES(6)] __attribute__((aligned(16)));
    sep_ccec_pub_ctx_t *key = (sep_ccec_pub_ctx_t *)(void *)key_storage;
    assert(sep_ccec_x963_import_pub(cp, sizeof(encoded), encoded, key) == 0);
    assert(memcmp(key->words, generator->xyz, 12 * sizeof(sep_u64)) == 0);

    sep_u8 compressed[49];
    compressed[0] = 3;
    memcpy(compressed + 1, encoded + 1, 48);
    assert(sep_ccec_x963_import_pub(cp, sizeof(compressed), compressed, key) == 0);
    assert(memcmp(key->words, generator->xyz, 12 * sizeof(sep_u64)) == 0);

    encoded[0] = 5;
    assert(sep_ccec_x963_import_pub(cp, sizeof(encoded), encoded, key) == -7);
    encoded[0] = 4;
    encoded[96] ^= 1;
    assert(sep_ccec_x963_import_pub(cp, sizeof(encoded), encoded, key) == -7);

    sep_u64 zero[6] = { 0, 0, 0, 0, 0, 0 };
    assert(sep_ccec_validate_scalar(cp, zero) == -1);
    sep_u64 order[6];
    scalar_from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        order
    );
    assert(sep_ccec_validate_scalar(cp, order) == -1);
    zero[0] = 1;
    assert(sep_ccec_validate_scalar(cp, zero) == 0);
}

static void test_group_properties(void) {
    const sep_ccec_cp_t *cp = sep_ccec_cp_384();
    sep_u64 generator_words[12];
    sep_ccec_affine_point_t *generator = affine(generator_words);
    point_from_hex(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        generator
    );
    sep_u64 g_words[18];
    sep_ccec_projective_point_t *g = projective(g_words);
    assert(sep_ccec_projectify_ws(NULL, cp, g, generator, NULL) == 0);
    sep_u64 previous_words[18];
    sep_ccec_projective_point_t *previous = projective(previous_words);
    memcpy(previous_words, g_words, sizeof(g_words));
    for (sep_u64 k = 2; k <= 12; ++k) {
        sep_u64 expected_words[18];
        sep_u64 sum_words[18];
        sep_ccec_projective_point_t *expected = projective(expected_words);
        sep_ccec_projective_point_t *sum = projective(sum_words);
        sep_u64 scalar[6] = { k, 0, 0, 0, 0, 0 };
        assert(sep_ccec_mult_ws(
            NULL,
            cp,
            expected,
            scalar,
            sep_ccn_bitlen(6, scalar),
            g
        ) == 0);
        sep_ccec_full_add_ws(NULL, cp, sum, previous, g);
        sep_u64 expected_affine_words[12];
        sep_u64 sum_affine_words[12];
        assert(sep_ccec_affinify_ws(
            NULL,
            cp,
            affine(expected_affine_words),
            expected
        ) == 0);
        assert(sep_ccec_affinify_ws(
            NULL,
            cp,
            affine(sum_affine_words),
            sum
        ) == 0);
        assert(memcmp(
            expected_affine_words,
            sum_affine_words,
            sizeof(sum_affine_words)
        ) == 0);
        memcpy(previous_words, sum_words, sizeof(sum_words));
    }
}

static void test_nist_cavp_ecdh_kat(void) {
    const sep_ccec_cp_t *cp = sep_ccec_cp_384();
    sep_u8 private_storage[SEP_CCEC_FULL_CTX_BYTES(6)]
        __attribute__((aligned(16))) = { 0 };
    sep_u8 peer_storage[SEP_CCEC_PUB_CTX_BYTES(6)]
        __attribute__((aligned(16))) = { 0 };
    sep_ccec_full_ctx_t *private_key =
        (sep_ccec_full_ctx_t *)(void *)private_storage;
    sep_ccec_pub_ctx_t *peer = (sep_ccec_pub_ctx_t *)(void *)peer_storage;
    private_key->cp = cp;
    peer->cp = cp;

    scalar_from_hex(
        "9dd9382c1fe0ad4aff511be07f286a0d11f6ddb307651c1b5d427faf781af64958f9610989c9c531cb10e46a19f9df71",
        private_key->words + 18
    );
    point_from_hex(
        "e133fdddbc9fd3084c00d25c672382adc6c736813a647df538680c9a98cd70d74c2137c32d3a9f2a55ddd97687694235",
        "f3884b67bf8d6ffe0c5f1ae8eac3f1e3306c927f5b708e0cea390eb0cf87067abfecc3ce7659d982ecbe468da6f03e8f",
        (sep_ccec_affine_point_t *)(void *)peer->words
    );
    assert(sep_ccec_make_pub_from_priv_ws(
        NULL,
        cp,
        NULL,
        private_key->words + 18,
        NULL,
        (sep_ccec_pub_ctx_t *)(void *)private_key
    ) == 0);

    sep_u8 shared_secret[48];
    sep_u8 expected[48];
    decode_hex(
        "8a2b354d3ecf2b4b825902cb1497432762540d93ba2563562c845125e5248aafb173a51996eac69f80ac3e1315cbbd28",
        expected,
        sizeof(expected)
    );
    sep_size_t shared_secret_length = sizeof(shared_secret);
    assert(sep_ccecdh_compute_shared_secret(
        private_key,
        peer,
        &shared_secret_length,
        shared_secret,
        NULL
    ) == 0);
    assert(shared_secret_length == sizeof(shared_secret));
    assert(memcmp(shared_secret, expected, sizeof(expected)) == 0);
}

static void test_ecdh_kat_and_keygen(void) {
    const sep_ccec_cp_t *cp = sep_ccec_cp_384();
    sep_u8 alice_storage[SEP_CCEC_FULL_CTX_BYTES(6)] __attribute__((aligned(16)));
    sep_u8 bob_storage[SEP_CCEC_FULL_CTX_BYTES(6)] __attribute__((aligned(16)));
    sep_ccec_full_ctx_t *alice = (sep_ccec_full_ctx_t *)(void *)alice_storage;
    sep_ccec_full_ctx_t *bob = (sep_ccec_full_ctx_t *)(void *)bob_storage;
    alice->cp = cp;
    bob->cp = cp;
    scalar_from_hex("123456789abcdef123456789abcdef", alice->words + 18);
    scalar_from_hex("fedcba9876543210fedcba987654321", bob->words + 18);
    assert(sep_ccec_make_pub_from_priv_ws(
        NULL,
        cp,
        NULL,
        alice->words + 18,
        NULL,
        (sep_ccec_pub_ctx_t *)alice
    ) == 0);
    assert(sep_ccec_make_pub_from_priv_ws(
        NULL,
        cp,
        NULL,
        bob->words + 18,
        NULL,
        (sep_ccec_pub_ctx_t *)bob
    ) == 0);

    sep_u8 alice_secret[48];
    sep_u8 bob_secret[48];
    sep_u8 expected[48];
    decode_hex(
        "16455886420cf4943f19e7f165c80091bc22d9610473436c37c8eea745f935a16b94c88b1437d3e0564c164c67e2d967",
        expected,
        sizeof(expected)
    );
    sep_size_t alice_length = sizeof(alice_secret);
    sep_size_t bob_length = sizeof(bob_secret);
    assert(sep_ccecdh_compute_shared_secret(
        alice,
        (sep_ccec_pub_ctx_t *)bob,
        &alice_length,
        alice_secret,
        NULL
    ) == 0);
    assert(sep_ccecdh_compute_shared_secret(
        bob,
        (sep_ccec_pub_ctx_t *)alice,
        &bob_length,
        bob_secret,
        NULL
    ) == 0);
    assert(alice_length == 48 && bob_length == 48);
    assert(memcmp(alice_secret, expected, 48) == 0);
    assert(memcmp(alice_secret, bob_secret, 48) == 0);

    sep_size_t short_length = 47;
    assert(sep_ccecdh_compute_shared_secret(
        alice,
        (sep_ccec_pub_ctx_t *)bob,
        &short_length,
        alice_secret,
        NULL
    ) == -1);
    assert(short_length == 0);

    deterministic_rng_t rng = { .generate = deterministic_generate };
    rng.scalar[0] = 5;
    for (sep_size_t i = 1; i < 6; ++i) {
        rng.scalar[i] = 0;
    }
    sep_u8 generated_storage[SEP_CCEC_FULL_CTX_BYTES(6)]
        __attribute__((aligned(16)));
    sep_ccec_full_ctx_t *generated =
        (sep_ccec_full_ctx_t *)(void *)generated_storage;
    assert(sep_ccecdh_generate_key(
        cp,
        (sep_ccrng_state_t *)&rng,
        generated
    ) == 0);
    assert(generated->words[18] == 5);
    assert(sep_ccecdh_pairwise_consistency_check_ws(
        NULL,
        generated,
        NULL,
        (sep_ccrng_state_t *)&rng
    ) == 0);
}

int main(void) {
    test_curve_and_point_kats();
    test_import_and_invalid_inputs();
    test_group_properties();
    test_nist_cavp_ecdh_kat();
    test_ecdh_kat_and_keygen();
    puts("ECC tests passed");
    return 0;
}
