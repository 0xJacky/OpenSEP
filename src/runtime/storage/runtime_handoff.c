#include "open_secure_rom/runtime_handoff.h"

#include "open_secure_rom/runtime.h"

static sep_u8 platform_runtime_handoff_metadata[28]
    OPEN_SECURE_ROM_SECTION(".runtime_handoff_metadata");

void sep_platform_runtime_mapping_commit(void) {}

void sep_platform_copy_runtime_handoff_metadata(
    void *output,
    sep_size_t output_length
) {
    if (output_length != sizeof(platform_runtime_handoff_metadata)) {
        sep_fatal_wait_loop();
    }
    sep_memmove(
        output,
        platform_runtime_handoff_metadata,
        sizeof(platform_runtime_handoff_metadata)
    );
}

void sep_runtime_provider_context_ready_hook(const void *provider_context) {
    (void)provider_context;
}

void sep_runtime_regions_commit_barrier_hook(void) {}

void sep_runtime_primary_handoff_pre_hook(void) {}

void sep_runtime_alternate_handoff_pre_hook(void) {}

void sep_runtime_primary_handoff_post_hook(void) {}

void sep_runtime_alternate_handoff_post_hook(void) {}
