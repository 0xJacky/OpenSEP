#ifndef OPEN_SECURE_ROM_CRYPTO_WORKSPACE_H
#define OPEN_SECURE_ROM_CRYPTO_WORKSPACE_H

#include "open_secure_rom/types.h"

sep_size_t sep_sizeof_cc_unit(void);
sep_u64 *sep_cc_ws_alloc(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count
);
void sep_cc_ws_free_stack(sep_cc_ws_t *workspace);
void sep_cc_try_abort_if(sep_bool condition, const char *message);

#endif
