#include "open_secure_rom/platform.h"

#include "open_secure_rom/crypto_hmac.h"
#include "open_secure_rom/event_log.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/runtime.h"

typedef struct runtime_authentication_state {
    sep_bool initialized;
    sep_u8 primary_key[32];
    sep_u8 authentication_key[32];
} runtime_authentication_state_t;

static runtime_authentication_state_t runtime_authentication_state
    OPEN_SECURE_ROM_SECTION(".runtime_authentication_state");

static const char runtime_authentication_key_label[5] = {
    (char)0xff, 'A', 'M', 'K', '\0',
};

void sep_platform_runtime_authentication_state_initialize(void) {
    if (sep_platform_zero_result_stub() != 0) {
        sep_panic_with_reason_and_pc(
            535,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }
    if (runtime_authentication_state.initialized == 1) {
        sep_panic_with_reason_and_pc(
            537,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }
    const sep_u32 required =
        sep_platform_required_capability_mask_zero_stub();
    const sep_u32 available = sep_platform_capability_mask_zero_stub(0x1e);
    if ((required & ~available) != 0) {
        sep_panic_with_reason_and_pc(
            547,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }

    sep_u8 seed[24];
    sep_memzero(seed, sizeof(seed));
    sep_platform_key_material_transform_noop(
        runtime_authentication_key_label,
        seed,
        sizeof(seed),
        runtime_authentication_state.primary_key,
        sizeof(runtime_authentication_state.primary_key)
    );
    seed[0] = 1;
    sep_platform_key_material_transform_noop(
        runtime_authentication_key_label,
        seed,
        sizeof(seed),
        runtime_authentication_state.authentication_key,
        sizeof(runtime_authentication_state.authentication_key)
    );
    runtime_authentication_state.initialized = 1;
}

void __attribute__((noreturn))
sep_platform_runtime_authentication_verify_or_panic(void) {
    if (sep_platform_zero_result_stub() != 0) {
        sep_panic_with_reason_and_pc(
            566,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }
    if ((*(const volatile sep_u8 *)(uintptr_t)0x04020680 & 1) == 0) {
        sep_panic_with_reason_and_pc(
            113,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }
    if ((runtime_authentication_state.initialized & 1) == 0) {
        sep_panic_with_reason_and_pc(
            115,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }
    if (!sep_checked_bytes32_any_nonzero(
        runtime_authentication_state.authentication_key
    )) {
        sep_panic_with_reason_and_pc(
            122,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }

    const sep_checked_bytes32_t computed =
        sep_checked_bytes32_hmac_sha256(
            (const void *)(uintptr_t)0x04020700,
            0xe0,
            runtime_authentication_state.authentication_key,
            sizeof(runtime_authentication_state.authentication_key)
        );
    sep_u8 expected_bytes[16];
    sep_platform_configuration_read(0xe0, expected_bytes, sizeof(expected_bytes));
    const sep_checked_bytes32_t expected =
        sep_checked_bytes32_from_data(expected_bytes, sizeof(expected_bytes));
    if (sep_checked_bytes32_compare_prefix(&expected, &computed, 16) != 0) {
        sep_protocol_event_log_append(0x80080004);
        sep_panic_with_reason_and_pc(
            135,
            (sep_u64)(uintptr_t)__builtin_return_address(0)
        );
    }
    sep_panic_with_reason_and_pc(
        149,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}
