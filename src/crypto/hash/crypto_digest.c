#include "open_secure_rom/crypto_digest.h"

#include "open_secure_rom/runtime.h"

static const sep_u8 sha1_oid[] = {
    0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
};
static const sep_u8 sha256_oid[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
};
static const sep_u8 sha384_oid[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
};
static const sep_u8 sha512_oid[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
};

static const sep_u32 sha1_initial_state[5] = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};
static const sep_u32 sha256_initial_state[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};
static const sep_u64 sha384_initial_state[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};
static const sep_u64 sha512_initial_state[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static sep_u32 rotate_left32(sep_u32 value, sep_u32 shift) {
    return (value << shift) | (value >> (32 - shift));
}

static sep_u64 rotate_left64(sep_u64 value, sep_u32 shift) {
    if (shift == 0) {
        return value;
    }
    return (value << shift) | (value >> (64 - shift));
}

static sep_u32 load_be32(const sep_u8 *bytes) {
    return ((sep_u32)bytes[0] << 24) |
        ((sep_u32)bytes[1] << 16) |
        ((sep_u32)bytes[2] << 8) |
        bytes[3];
}

static void store_be32(sep_u8 *bytes, sep_u32 value) {
    bytes[0] = (sep_u8)(value >> 24);
    bytes[1] = (sep_u8)(value >> 16);
    bytes[2] = (sep_u8)(value >> 8);
    bytes[3] = (sep_u8)value;
}

static void store_be64(sep_u8 *bytes, sep_u64 value) {
    for (sep_size_t index = 0; index < 8; ++index) {
        bytes[index] = (sep_u8)(value >> (56 - index * 8));
    }
}

void sep_sha1_compress_blocks_armv8(
    sep_u32 *state,
    sep_size_t block_count,
    const void *blocks
) {
    const sep_u8 *input = blocks;
    while (block_count != 0) {
        sep_u32 words[80];
        for (sep_size_t index = 0; index < 16; ++index) {
            words[index] = load_be32(&input[index * 4]);
        }
        for (sep_size_t index = 16; index < 80; ++index) {
            words[index] = rotate_left32(
                words[index - 3] ^ words[index - 8] ^
                    words[index - 14] ^ words[index - 16],
                1
            );
        }

        sep_u32 a = state[0];
        sep_u32 b = state[1];
        sep_u32 c = state[2];
        sep_u32 d = state[3];
        sep_u32 e = state[4];
        for (sep_size_t index = 0; index < 80; ++index) {
            sep_u32 function;
            sep_u32 constant;
            if (index < 20) {
                function = (b & c) | (~b & d);
                constant = 0x5a827999;
            } else if (index < 40) {
                function = b ^ c ^ d;
                constant = 0x6ed9eba1;
            } else if (index < 60) {
                function = (b & c) | (b & d) | (c & d);
                constant = 0x8f1bbcdc;
            } else {
                function = b ^ c ^ d;
                constant = 0xca62c1d6;
            }
            const sep_u32 temporary = rotate_left32(a, 5) + function +
                e + constant + words[index];
            e = d;
            d = c;
            c = rotate_left32(b, 30);
            b = a;
            a = temporary;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        input += 64;
        --block_count;
    }
}

void sep_ccsha1_vng_arm_compress(
    sep_u32 *state,
    sep_size_t block_count,
    const void *blocks
) {
    sep_sha1_compress_blocks_armv8(state, block_count, blocks);
}

static sep_u64 *context_bit_count(sep_ccdigest_ctx_t *context) {
    return (sep_u64 *)&context->bytes[0];
}

static const sep_u64 *constant_context_bit_count(
    const sep_ccdigest_ctx_t *context
) {
    return (const sep_u64 *)&context->bytes[0];
}

static void *context_state(sep_ccdigest_ctx_t *context) {
    return &context->bytes[8];
}

static const void *constant_context_state(
    const sep_ccdigest_ctx_t *context
) {
    return &context->bytes[8];
}

static sep_u8 *context_buffer(
    const sep_ccdigest_info_t *descriptor,
    sep_ccdigest_ctx_t *context
) {
    return &context->bytes[8 + descriptor->state_size];
}

static sep_u32 *context_buffered_count(
    const sep_ccdigest_info_t *descriptor,
    sep_ccdigest_ctx_t *context
) {
    return (sep_u32 *)&context->bytes[
        8 + descriptor->state_size + descriptor->block_size
    ];
}

static const sep_u32 *constant_context_buffered_count(
    const sep_ccdigest_info_t *descriptor,
    const sep_ccdigest_ctx_t *context
) {
    return (const sep_u32 *)&context->bytes[
        8 + descriptor->state_size + descriptor->block_size
    ];
}

static sep_size_t digest_context_used_size(
    const sep_ccdigest_info_t *descriptor
) {
    const sep_size_t size = 8 + descriptor->state_size +
        descriptor->block_size + 4;
    if (size > sizeof(sep_ccdigest_ctx_t)) {
        sep_fatal_wait_loop();
    }
    return size;
}

static void compress_sha1(
    void *state,
    sep_size_t block_count,
    const void *blocks
) {
    sep_ccsha1_vng_arm_compress(state, block_count, blocks);
}

static void compress_sha256(
    void *state,
    sep_size_t block_count,
    const void *blocks
) {
    sep_sha256_compress_blocks(state, block_count, blocks);
}

static void compress_sha512(
    void *state,
    sep_size_t block_count,
    const void *blocks
) {
    sep_sha512_compress_blocks(state, block_count, blocks);
}

static void compress_sha512_scalar(
    void *state,
    sep_size_t block_count,
    const void *blocks
) {
    sep_sha512_compress_blocks_scalar(state, block_count, blocks);
}

static void final_sha2_64(
    const sep_ccdigest_info_t *descriptor,
    const sep_ccdigest_ctx_t *context,
    void *digest
) {
    sep_sha2_64_finalize(descriptor, (void *)context, digest);
}

static const sep_ccdigest_info_t sha1_descriptor = {
    20, 20, 64, sizeof(sha1_oid), sha1_oid, sha1_initial_state,
    compress_sha1, sep_ccdigest_final_64be, 0x20, 0,
};
static const sep_ccdigest_info_t sha256_descriptor = {
    32, 32, 64, sizeof(sha256_oid), sha256_oid, sha256_initial_state,
    compress_sha256, sep_ccdigest_final_64be, 0x02, 0,
};
static const sep_ccdigest_info_t sha384_descriptor = {
    48, 64, 128, sizeof(sha384_oid), sha384_oid, sha384_initial_state,
    compress_sha512, final_sha2_64, 0x2a, 0,
};
static const sep_ccdigest_info_t sha384_scalar_descriptor
    __attribute__((used)) = {
    48, 64, 128, sizeof(sha384_oid), sha384_oid, sha384_initial_state,
    compress_sha512_scalar, final_sha2_64, 0x29, 0,
};
static const sep_ccdigest_info_t sha512_descriptor = {
    64, 64, 128, sizeof(sha512_oid), sha512_oid, sha512_initial_state,
    compress_sha512, final_sha2_64, 0, 0,
};

const sep_ccdigest_info_t *sep_ccsha256_di(void) {
    return &sha256_descriptor;
}

const sep_ccdigest_info_t *sep_digest_info_for_bit_length(
    sep_size_t digest_bit_length
) {
    switch (digest_bit_length) {
    case 160:
        return &sha1_descriptor;
    case 256:
        return &sha256_descriptor;
    case 384:
        return &sha384_descriptor;
    default:
        sep_fatal_wait_loop();
    }
}

const sep_ccdigest_info_t *open_secure_rom_sha512_di(void) {
    return &sha512_descriptor;
}

void sep_ccdigest_init(
    const sep_ccdigest_info_t *descriptor,
    sep_ccdigest_ctx_t *context
) {
    (void)digest_context_used_size(descriptor);
    *context_bit_count(context) = 0;
    sep_memmove(
        context_state(context),
        descriptor->initial_state,
        descriptor->state_size
    );
    *context_buffered_count(descriptor, context) = 0;
}

void sep_ccdigest_update(
    const sep_ccdigest_info_t *descriptor,
    sep_ccdigest_ctx_t *context,
    sep_size_t length,
    const void *data
) {
    (void)digest_context_used_size(descriptor);
    const sep_u8 *input = data;
    sep_u32 buffered = *context_buffered_count(descriptor, context);
    while (length != 0) {
        if (buffered == 0 && length > descriptor->block_size) {
            const sep_size_t block_count = length / descriptor->block_size;
            const sep_size_t consumed = block_count * descriptor->block_size;
            descriptor->compress(context_state(context), block_count, input);
            *context_bit_count(context) += (sep_u64)consumed * 8;
            input += consumed;
            length -= consumed;
            continue;
        }

        sep_size_t consumed = descriptor->block_size - buffered;
        if (consumed > length) {
            consumed = length;
        }
        sep_memmove(
            &context_buffer(descriptor, context)[buffered],
            input,
            consumed
        );
        buffered += (sep_u32)consumed;
        input += consumed;
        length -= consumed;
        if (buffered == descriptor->block_size) {
            descriptor->compress(
                context_state(context),
                1,
                context_buffer(descriptor, context)
            );
            *context_bit_count(context) += (sep_u64)buffered * 8;
            buffered = 0;
        }
        *context_buffered_count(descriptor, context) = buffered;
    }
}

static void finalize_with_64_bit_length(
    const sep_ccdigest_info_t *descriptor,
    const sep_ccdigest_ctx_t *context,
    void *digest,
    sep_size_t length_field_reservation,
    sep_size_t output_word_size
) {
    sep_ccdigest_ctx_t temporary;
    sep_memzero(&temporary, sizeof(temporary));
    sep_memmove(
        &temporary,
        context,
        digest_context_used_size(descriptor)
    );
    sep_u8 *buffer = context_buffer(descriptor, &temporary);
    sep_u32 buffered = *constant_context_buffered_count(
        descriptor,
        &temporary
    );
    const sep_u64 total_bits = *constant_context_bit_count(&temporary) +
        (sep_u64)buffered * 8;

    buffer[buffered++] = 0x80;
    const sep_size_t length_offset = descriptor->block_size -
        length_field_reservation;
    if (buffered > length_offset) {
        sep_memzero(&buffer[buffered], descriptor->block_size - buffered);
        descriptor->compress(context_state(&temporary), 1, buffer);
        sep_memzero(buffer, descriptor->block_size);
        buffered = 0;
    }
    sep_memzero(&buffer[buffered], descriptor->block_size - buffered);
    store_be64(
        &buffer[descriptor->block_size - 8],
        total_bits
    );
    descriptor->compress(context_state(&temporary), 1, buffer);

    sep_u8 *output = digest;
    if (output_word_size == 4) {
        const sep_u32 *state = constant_context_state(&temporary);
        for (sep_size_t offset = 0; offset < descriptor->output_size; offset += 4) {
            store_be32(&output[offset], state[offset / 4]);
        }
    } else {
        const sep_u64 *state = constant_context_state(&temporary);
        for (sep_size_t offset = 0; offset < descriptor->output_size; offset += 8) {
            store_be64(&output[offset], state[offset / 8]);
        }
    }
    sep_memzero(&temporary, sizeof(temporary));
}

void sep_ccdigest_final_64be(
    const sep_ccdigest_info_t *descriptor,
    const sep_ccdigest_ctx_t *context,
    void *digest
) {
    finalize_with_64_bit_length(descriptor, context, digest, 8, 4);
}

void sep_sha2_64_finalize(
    const void *descriptor,
    void *context,
    void *digest
) {
    finalize_with_64_bit_length(
        descriptor,
        context,
        digest,
        16,
        8
    );
}

void sep_ccdigest_internal(
    const sep_ccdigest_info_t *descriptor,
    sep_size_t length,
    const void *data,
    void *digest
) {
    sep_ccdigest_ctx_t context;
    sep_memzero(&context, sizeof(context));
    sep_ccdigest_init(descriptor, &context);
    sep_ccdigest_update(descriptor, &context, length, data);
    descriptor->final(descriptor, &context, digest);
    sep_memzero(&context, sizeof(context));
}

void sep_ccdigest(
    const sep_ccdigest_info_t *descriptor,
    sep_size_t length,
    const void *data,
    void *digest
) {
    sep_ccdigest_internal(descriptor, length, data, digest);
}

void sep_digest_by_bit_length(
    sep_size_t digest_bit_length,
    const void *data,
    sep_size_t data_length,
    void *digest,
    sep_size_t digest_length
) {
    if (digest_length > SIZE_MAX / 8 ||
        digest_bit_length != digest_length * 8) {
        sep_fatal_wait_loop();
    }
    sep_ccdigest(
        sep_digest_info_for_bit_length(digest_bit_length),
        data_length,
        data,
        digest
    );
}

void sep_cckeccak_f1600_c(sep_u64 state[25]) {
    static const sep_u64 round_constants[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL,
    };
    static const sep_u8 rotation_offsets[25] = {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    };

    for (sep_size_t round = 0; round < 24; ++round) {
        sep_u64 column_parity[5];
        sep_u64 mixed[25];
        for (sep_size_t x = 0; x < 5; ++x) {
            column_parity[x] = state[x] ^ state[x + 5] ^
                state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (sep_size_t x = 0; x < 5; ++x) {
            const sep_u64 theta = column_parity[(x + 4) % 5] ^
                rotate_left64(column_parity[(x + 1) % 5], 1);
            for (sep_size_t y = 0; y < 5; ++y) {
                state[x + 5 * y] ^= theta;
            }
        }
        for (sep_size_t x = 0; x < 5; ++x) {
            for (sep_size_t y = 0; y < 5; ++y) {
                const sep_size_t source = x + 5 * y;
                const sep_size_t destination_y = (2 * x + 3 * y) % 5;
                mixed[y + 5 * destination_y] = rotate_left64(
                    state[source],
                    rotation_offsets[source]
                );
            }
        }
        for (sep_size_t y = 0; y < 5; ++y) {
            for (sep_size_t x = 0; x < 5; ++x) {
                state[x + 5 * y] = mixed[x + 5 * y] ^
                    (~mixed[(x + 1) % 5 + 5 * y] &
                        mixed[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= round_constants[round];
    }
}
