#ifndef OPEN_SECURE_ROM_CMAC_H
#define OPEN_SECURE_ROM_CMAC_H

#include "open_secure_rom/aes.h"

typedef struct sep_cccmac_ctx sep_cccmac_ctx_t;

struct sep_cccmac_ctx {
    sep_u8 subkey1[16];
    sep_u8 subkey2[16];
    sep_u8 block[16];
    sep_size_t block_length;
    sep_size_t processed_length;
    const sep_ccmode_cbc_t *cbc;
    sep_u8 mode_context[1];
};

#define SEP_CCMAC_CONTEXT_SIZE(cbc) \
    (sizeof(sep_cccmac_ctx_t) + (cbc)->size + (cbc)->block_size)

int sep_cccmac_generate_subkeys(
        const sep_ccmode_cbc_t *cbc,
        sep_size_t key_length,
        const void *key,
        sep_u8 subkey1[16],
        sep_u8 subkey2[16]
    );
int sep_cccmac_init_internal(
    const sep_ccmode_cbc_t *cbc,
    sep_cccmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
);
int sep_cccmac_init(
    const sep_ccmode_cbc_t *cbc,
    sep_cccmac_ctx_t *context,
    sep_size_t key_length,
    const void *key
);
int sep_cccmac_update_internal(
    sep_cccmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
);
int sep_cccmac_update(
    sep_cccmac_ctx_t *context,
    sep_size_t data_length,
    const void *data
);
int sep_cccmac_final_generate_internal(
    sep_cccmac_ctx_t *context,
    sep_size_t mac_length,
    void *mac
);
int sep_cccmac_final_generate(
    sep_cccmac_ctx_t *context,
    sep_size_t mac_length,
    void *mac
);
int sep_cccmac_final_verify_internal(
    sep_cccmac_ctx_t *context,
    sep_size_t expected_mac_length,
    const void *expected_mac
);
int sep_cccmac_final_verify(
    sep_cccmac_ctx_t *context,
    sep_size_t expected_mac_length,
    const void *expected_mac
);

int sep_ccnistkdf_ctr_cmac_fixed_internal(
    const sep_ccmode_cbc_t *cbc,
    sep_u8 counter_width,
    sep_size_t kdk_length,
    const void *kdk,
    sep_size_t fixed_data_length,
    const void *fixed_data,
    sep_size_t derived_key_length,
    void *derived_key
);
int sep_ccnistkdf_ctr_cmac_fixed(
    const sep_ccmode_cbc_t *cbc,
    sep_u8 counter_width,
    sep_size_t kdk_length,
    const void *kdk,
    sep_size_t fixed_data_length,
    const void *fixed_data,
    sep_size_t derived_key_length,
    void *derived_key
);
void sep_ccnistkdf_ctr_cmac_prf_eval(
    sep_cccmac_ctx_t *cmac,
    sep_u8 counter_width,
    sep_u32 counter,
    sep_size_t fixed_data_length,
    const void *fixed_data,
    void *result
);

#endif
