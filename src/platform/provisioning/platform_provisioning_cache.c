#include "open_secure_rom/platform.h"

#include "open_secure_rom/provisioning.h"
#include "open_secure_rom/runtime.h"

typedef struct {
    sep_bool initialized;
    sep_optional_research_seed_t research_seed;
    sep_optional_configuration_key48_t configuration_key;
} platform_provisioning_cache_t;

static platform_provisioning_cache_t platform_provisioning_cache
    OPEN_SECURE_ROM_SECTION(".platform_provisioning_cache")
    __attribute__((used));

_Static_assert(
    offsetof(platform_provisioning_cache_t, research_seed) == 1,
    "research seed cache ABI"
);
_Static_assert(
    offsetof(platform_provisioning_cache_t, configuration_key) == 22,
    "configuration key cache ABI"
);
_Static_assert(
    sizeof(platform_provisioning_cache_t) == 71,
    "provisioning cache ABI"
);

void sep_platform_cache_provisioning_values(void) {
    if (platform_provisioning_cache.initialized >= 2) {
        sep_fatal_wait_loop();
    }
    if (platform_provisioning_cache.initialized == 0) {
        sep_platform_provisioning_initialize();
        platform_provisioning_cache.configuration_key =
            sep_platform_provisioning_get_optional_key48();
        platform_provisioning_cache.research_seed =
            sep_platform_provisioning_get_optional_research_seed();
        platform_provisioning_cache.initialized = 1;
    }
}

sep_optional_configuration_key48_t
sep_platform_get_cached_optional_key48(void) {
    sep_platform_cache_provisioning_values();
    return platform_provisioning_cache.configuration_key;
}

sep_optional_research_seed_t
sep_platform_get_cached_optional_research_seed(void) {
    sep_platform_cache_provisioning_values();
    return platform_provisioning_cache.research_seed;
}
