#include "open_secure_rom/runtime_handoff.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

int main(void) {
    sep_u8 metadata[28];
    sep_platform_copy_runtime_handoff_metadata(metadata, sizeof(metadata));
    for (sep_size_t index = 0; index < sizeof(metadata); ++index) {
        assert(metadata[index] == 0);
    }

    sep_platform_runtime_mapping_commit();
    sep_runtime_provider_context_ready_hook(metadata);
    sep_runtime_regions_commit_barrier_hook();
    sep_runtime_primary_handoff_pre_hook();
    sep_runtime_alternate_handoff_pre_hook();
    sep_runtime_primary_handoff_post_hook();
    sep_runtime_alternate_handoff_post_hook();
}
