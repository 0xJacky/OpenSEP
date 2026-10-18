#include "open_secure_rom/platform.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

sep_u32 sep_protocol_event_log_append(sep_u32 event_code) {
    return event_code;
}

int main(void) {
    for (sep_u32 packed = 0; packed < 0x100; ++packed) {
        const sep_runtime_feature_flags_t flags =
            sep_runtime_feature_flags_decode(packed);
        assert(flags.valid == 1);
        assert(sep_runtime_feature_flags_pack(&flags) == packed);
        sep_runtime_feature_flags_validate_platform_support(&flags);
    }
    sep_runtime_feature_flags_t flags =
        sep_runtime_feature_flags_decode(0x13);
    sep_runtime_feature_flags_apply(&flags);
    flags = sep_runtime_feature_flags_decode(0xe0);
    sep_runtime_feature_flags_apply(&flags);
}
