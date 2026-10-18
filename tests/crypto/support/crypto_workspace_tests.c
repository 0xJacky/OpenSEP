#include "open_secure_rom/crypto_workspace.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

int main(void) {
    sep_u64 storage[8];
    for (sep_size_t index = 0; index < 8; ++index) {
        storage[index] = UINT64_MAX;
    }
    sep_cc_ws_t workspace = {
        .ctx = storage,
        .nunits = 8,
        .offset = 0,
    };
    assert(sep_sizeof_cc_unit() == 8);
    assert(sep_cc_ws_alloc(&workspace, 3) == storage);
    assert(sep_cc_ws_alloc(&workspace, 5) == storage + 3);
    assert(workspace.offset == 8);
    sep_cc_ws_free_stack(&workspace);
    assert(workspace.ctx == 0);
    assert(workspace.nunits == 0);
    assert(workspace.offset == 0);
    for (sep_size_t index = 0; index < 8; ++index) {
        assert(storage[index] == 0);
    }
}
