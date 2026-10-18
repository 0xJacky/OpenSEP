#ifndef OPEN_SECURE_ROM_CRYPTO_DIGEST_H
#define OPEN_SECURE_ROM_CRYPTO_DIGEST_H

#include "open_secure_rom/types.h"

enum {
    SEP_CCDIGEST_MAX_STATE_SIZE = 64,
    SEP_CCDIGEST_MAX_BLOCK_SIZE = 128,
    SEP_CCDIGEST_CONTEXT_SIZE = 208,
};

typedef void (*sep_ccdigest_compress_fn)(
    void *state,
    sep_size_t block_count,
    const void *blocks
);
typedef void (*sep_ccdigest_final_fn)(
    const sep_ccdigest_info_t *descriptor,
    const sep_ccdigest_ctx_t *context,
    void *digest
);

struct sep_ccdigest_info {
    sep_size_t output_size;
    sep_size_t state_size;
    sep_size_t block_size;
    sep_size_t oid_size;
    const sep_u8 *oid;
    const void *initial_state;
    sep_ccdigest_compress_fn compress;
    sep_ccdigest_final_fn final;
    sep_u64 implementation;
    sep_u64 reserved;
};

struct sep_ccdigest_ctx {
    sep_u8 bytes[SEP_CCDIGEST_CONTEXT_SIZE];
} __attribute__((aligned(8)));

_Static_assert(sizeof(sep_ccdigest_info_t) == 80, "digest descriptor ABI");
_Static_assert(
    offsetof(sep_ccdigest_info_t, initial_state) == 40,
    "digest initial state offset"
);
_Static_assert(
    offsetof(sep_ccdigest_info_t, compress) == 48,
    "digest compressor offset"
);
_Static_assert(
    offsetof(sep_ccdigest_info_t, final) == 56,
    "digest finalizer offset"
);
_Static_assert(
    sizeof(sep_ccdigest_ctx_t) == SEP_CCDIGEST_CONTEXT_SIZE,
    "digest context capacity"
);

const sep_ccdigest_info_t *sep_ccsha256_di(void);
const sep_ccdigest_info_t *sep_digest_info_for_bit_length(
    sep_size_t digest_bit_length
);
void sep_digest_by_bit_length(
    sep_size_t digest_bit_length,
    const void *data,
    sep_size_t data_length,
    void *digest,
    sep_size_t digest_length
);
void sep_ccdigest_internal(
    const sep_ccdigest_info_t *descriptor,
    sep_size_t length,
    const void *data,
    void *digest
);
void sep_ccdigest(
    const sep_ccdigest_info_t *descriptor,
    sep_size_t length,
    const void *data,
    void *digest
);
void sep_ccdigest_final_64be(
    const sep_ccdigest_info_t *descriptor,
    const sep_ccdigest_ctx_t *context,
    void *digest
);
void sep_ccdigest_init(
    const sep_ccdigest_info_t *descriptor,
    sep_ccdigest_ctx_t *context
);
void sep_ccdigest_update(
    const sep_ccdigest_info_t *descriptor,
    sep_ccdigest_ctx_t *context,
    sep_size_t length,
    const void *data
);

void sep_ccsha1_vng_arm_compress(
    sep_u32 *state,
    sep_size_t block_count,
    const void *blocks
);
void sep_sha1_compress_blocks_armv8(
    sep_u32 *state,
    sep_size_t block_count,
    const void *blocks
);
void sep_sha256_compress_blocks(
    sep_u32 *state,
    sep_size_t block_count,
    const void *blocks
);
void sep_sha256_compress_blocks_armv8(
    sep_u32 *state,
    sep_size_t block_count,
    const void *blocks
);
void sep_sha512_compress_blocks(
    sep_u64 *state,
    sep_size_t block_count,
    const void *blocks
);
void sep_sha512_compress_blocks_scalar(
    sep_u64 *state,
    sep_size_t block_count,
    const void *blocks
);
void sep_sha512_compress_blocks_neon(
    sep_u64 *state,
    sep_size_t block_count,
    const void *blocks
);
void sep_sha2_64_finalize(
    const void *descriptor,
    void *context,
    void *digest
);
void sep_cckeccak_f1600_c(sep_u64 state[25]);

const sep_ccdigest_info_t *open_secure_rom_sha512_di(void);

#endif
