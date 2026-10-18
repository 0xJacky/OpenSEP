#ifndef OPEN_SECURE_ROM_RUNTIME_HANDOFF_H
#define OPEN_SECURE_ROM_RUNTIME_HANDOFF_H

#include "open_secure_rom/types.h"

void sep_platform_runtime_mapping_commit(void);
void sep_platform_copy_runtime_handoff_metadata(
    void *output,
    sep_size_t output_length
);
void sep_runtime_provider_context_ready_hook(const void *provider_context);
void sep_runtime_regions_commit_barrier_hook(void);
void sep_runtime_primary_handoff_pre_hook(void);
void sep_runtime_alternate_handoff_pre_hook(void);
void sep_runtime_primary_handoff_post_hook(void);
void sep_runtime_alternate_handoff_post_hook(void);

#endif
