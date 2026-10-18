#ifndef OPEN_SECURE_ROM_AES_H
#define OPEN_SECURE_ROM_AES_H

#include "open_secure_rom/types.h"

typedef struct sep_aes_key_context {
    sep_u8 round_keys[240];
    sep_u32 final_round_offset;
} sep_aes_key_context_t;

typedef struct sep_ccmode_cbc sep_ccmode_cbc_t;
typedef struct sep_ccmode_ecb sep_ccmode_ecb_t;
typedef struct sep_ccmode_ccm sep_ccmode_ccm_t;
typedef struct sep_ccccm_ctx sep_ccccm_ctx_t;
typedef struct sep_ccccm_nonce sep_ccccm_nonce_t;

struct sep_ccmode_cbc {
    sep_size_t size;
    sep_size_t block_size;
    int (*init)(
        const void *mode,
        void *context,
        sep_size_t key_length,
        const void *key
    );
    int (*cbc)(
        const void *context,
        void *iv,
        sep_size_t block_count,
        const void *input,
        void *output
    );
    const void *custom;
};

struct sep_ccmode_ecb {
    sep_size_t size;
    sep_size_t block_size;
    int (*init)(
        const void *mode,
        void *context,
        sep_size_t key_length,
        const void *key
    );
    int (*ecb)(
        const void *context,
        sep_size_t block_count,
        const void *input,
        void *output
    );
    const void *custom;
};

struct sep_ccmode_ccm {
    sep_size_t size;
    sep_size_t nonce_size;
    sep_size_t block_size;
    int (*init)(
        const sep_ccmode_ccm_t *mode,
        sep_ccccm_ctx_t *context,
        sep_size_t key_length,
        const void *key
    );
    int (*set_iv)(
        sep_ccccm_ctx_t *context,
        sep_ccccm_nonce_t *nonce_context,
        sep_size_t nonce_length,
        const void *nonce,
        sep_size_t tag_length,
        sep_size_t authenticated_data_length,
        sep_size_t plaintext_length
    );
    int (*cbcmac)(
        sep_ccccm_ctx_t *context,
        sep_ccccm_nonce_t *nonce_context,
        sep_size_t byte_count,
        const void *input
    );
    int (*ccm)(
        sep_ccccm_ctx_t *context,
        sep_ccccm_nonce_t *nonce_context,
        sep_size_t byte_count,
        const void *input,
        void *output
    );
    int (*finalize)(
        sep_ccccm_ctx_t *context,
        sep_ccccm_nonce_t *nonce_context,
        void *tag
    );
    int (*reset)(
        sep_ccccm_ctx_t *context,
        sep_ccccm_nonce_t *nonce_context
    );
    const sep_ccmode_ecb_t *custom;
    sep_bool encrypt;
};

struct sep_ccccm_ctx {
    const sep_ccmode_ecb_t *ecb;
    sep_u8 alignment[8];
    sep_aes_key_context_t key;
    sep_u8 tail_padding[20];
};

struct sep_ccccm_nonce {
    sep_u8 counter[16];
    sep_u8 mac_block[16];
    sep_u8 tag_mask[16];
    sep_u8 stream[16];
    sep_u32 state;
    sep_u32 stream_offset;
    sep_u32 mac_offset;
    sep_u32 alignment;
    sep_size_t nonce_length;
    sep_size_t tag_length;
};

sep_size_t sep_aes_key_length_bytes(sep_size_t key_bit_length);
int sep_aes_cbc_decrypt(
    void *output,
    const void *input,
    sep_size_t length,
    const sep_u8 *key,
    sep_size_t key_bit_length,
    const sep_u8 iv[16]
);
sep_bool sep_aes_cbc_decrypt_checked(
    void *output,
    const void *input,
    sep_size_t length,
    const sep_u8 *key,
    sep_size_t key_bit_length,
    const sep_u8 iv[16]
);
int sep_ccaes_arm_decrypt_cbc(
    const sep_aes_key_context_t *key,
    void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
);
int sep_ccaes_arm_encrypt_cbc(
    const sep_aes_key_context_t *key,
    void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
);
int sep_ccaes_cbc_decrypt_key_with_length_check(
    const void *mode,
    sep_aes_key_context_t *key,
    sep_size_t raw_key_length,
    const void *raw_key
);
int sep_ccaes_cbc_encrypt_key_with_length_check(
    const void *mode,
    sep_aes_key_context_t *key,
    sep_size_t raw_key_length,
    const void *raw_key
);
int sep_ccaes_ecb_encrypt_key_with_length_check(
    const void *mode,
    sep_aes_key_context_t *key,
    sep_size_t raw_key_length,
    const void *raw_key
);
int sep_ccaes_arm_encrypt_ecb(
    const sep_aes_key_context_t *key,
    sep_size_t block_count,
    const void *input,
    void *output
);
const sep_ccmode_cbc_t *sep_ccaes_cbc_encrypt_mode(void);
const sep_ccmode_ecb_t *sep_ccaes_ecb_encrypt_mode(void);
const sep_ccmode_ccm_t *sep_ccaes_ccm_encrypt_mode(void);
const sep_ccmode_ccm_t *sep_ccaes_ccm_decrypt_mode(void);
int sep_acceleratecrypto_ecb_aes_encrypt(
    const sep_aes_key_context_t *key,
    sep_u32 block_count,
    const void *input,
    void *output
);
void sep_ccaes_arm_encrypt_key128(
    const void *raw_key,
    sep_aes_key_context_t *expanded_key
);
void sep_ccaes_arm_encrypt_key192(
    const void *raw_key,
    sep_aes_key_context_t *expanded_key
);
void sep_ccaes_arm_encrypt_key256(
    const void *raw_key,
    sep_aes_key_context_t *expanded_key
);
int sep_ccaes_arm_encrypt_key(
    const void *mode,
    sep_aes_key_context_t *expanded_key,
    sep_size_t raw_key_length,
    const void *raw_key
);
int sep_ccaes_arm_decrypt_key(
    const void *mode,
    sep_aes_key_context_t *expanded_key,
    sep_size_t raw_key_length,
    const void *raw_key
);

int sep_cccbc_init_internal(
    const sep_ccmode_cbc_t *mode,
    void *context,
    sep_size_t key_length,
    const void *key
);
int sep_cccbc_set_iv_internal(
    const sep_ccmode_cbc_t *mode,
    void *iv_context,
    const void *iv
);
int sep_cccbc_update_internal(
    const sep_ccmode_cbc_t *mode,
    const void *context,
    void *iv_context,
    sep_size_t block_count,
    const void *input,
    void *output
);
int sep_cccbc_one_shot(
    const sep_ccmode_cbc_t *mode,
    sep_size_t key_length,
    const void *key,
    const void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
);
int sep_cccbc_one_shot_explicit_internal(
    const sep_ccmode_cbc_t *mode,
    sep_size_t key_length,
    const void *key,
    sep_size_t iv_length,
    const void *iv,
    sep_size_t block_count,
    const void *input,
    void *output
);

int sep_ccccm_one_shot_internal(
    const sep_ccmode_ccm_t *mode,
    sep_size_t key_length,
    const void *key,
    sep_size_t nonce_length,
    const void *nonce,
    sep_size_t data_length,
    const void *input,
    void *output,
    sep_size_t associated_data_length,
    const void *associated_data,
    sep_size_t tag_length,
    void *tag
);
int sep_ccccm_one_shot(
    const sep_ccmode_ccm_t *mode,
    sep_size_t key_length,
    const void *key,
    sep_size_t nonce_length,
    const void *nonce,
    sep_size_t data_length,
    const void *input,
    void *output,
    sep_size_t associated_data_length,
    const void *associated_data,
    sep_size_t tag_length,
    void *tag
);

int sep_ccmode_ccm_init(
    const sep_ccmode_ccm_t *mode,
    sep_ccccm_ctx_t *context,
    sep_size_t raw_key_length,
    const void *raw_key
);
int sep_ccmode_ccm_set_iv(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t nonce_length,
    const void *nonce,
    sep_size_t tag_length,
    sep_size_t authenticated_data_length,
    sep_size_t plaintext_length
);
void sep_ccmode_ccm_macdata(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_u32 new_block,
    sep_size_t byte_count,
    const void *input
);
int sep_ccmode_ccm_cbcmac(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input
);
void sep_ccmode_ccm_crypt(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
);
int sep_ccmode_ccm_encrypt(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
);
int sep_ccmode_ccm_decrypt(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
);
int sep_ccmode_ccm_encrypt_veneer(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
);
int sep_ccmode_ccm_decrypt_veneer(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    sep_size_t byte_count,
    const void *input,
    void *output
);
int sep_ccmode_ccm_finalize(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context,
    void *tag
);
int sep_ccmode_ccm_reset(
    sep_ccccm_ctx_t *context,
    sep_ccccm_nonce_t *nonce_context
);
void sep_ccmode_copy_ccm_descriptor(
    sep_ccmode_ccm_t *destination,
    const sep_ccmode_ccm_t *source
);

void sep_ccm128_encrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
);
void sep_ccm128_decrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
);
void sep_ccm192_encrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
);
void sep_ccm192_decrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
);
void sep_ccm256_encrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
);
void sep_ccm256_decrypt(
    const void *input,
    void *output,
    void *tag,
    sep_size_t block_count,
    const void *key_schedule,
    void *counter,
    sep_size_t counter_length
);

#endif
