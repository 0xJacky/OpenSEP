#include "open_secure_rom/crypto_workspace.h"

#include "open_secure_rom/runtime.h"

sep_size_t sep_sizeof_cc_unit(void) {
    return sizeof(sep_u64);
}

sep_u64 *sep_cc_ws_alloc(
    sep_cc_ws_t *workspace,
    sep_size_t limb_count
) {
    sep_u64 *allocation = &workspace->ctx[workspace->offset];
    workspace->offset += limb_count;
    sep_cc_try_abort_if(workspace->offset > workspace->nunits, "alloc ws");
    return allocation;
}

void sep_cc_ws_free_stack(sep_cc_ws_t *workspace) {
    sep_cc_try_abort_if(workspace->offset > workspace->nunits, "free ws");
    sep_memzero_via_runtime(
        sizeof(sep_u64) * workspace->nunits,
        workspace->ctx
    );
    workspace->ctx = 0;
    workspace->nunits = 0;
    workspace->offset = 0;
}

void sep_cc_try_abort_if(sep_bool condition, const char *message) {
    (void)condition;
    (void)message;
}
