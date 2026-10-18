#include "open_secure_rom/configuration_sink.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

int main(void) {
    const sep_u8 input[4] = {1, 2, 3, 4};
    sep_optional_configuration_key48_t key;
    sep_optional_configuration_key48_initialize_from_data(
        &key,
        input,
        sizeof(input)
    );
    assert(sep_optional_configuration_key48_is_present(&key) == 1);
    assert(sep_optional_configuration_key48_require_present(&key) == &key);
    for (sep_size_t index = 0; index < sizeof(input); ++index) {
        assert(key.bytes[index] == input[index]);
    }
    for (sep_size_t index = sizeof(input); index < sizeof(key.bytes); ++index) {
        assert(key.bytes[index] == 0);
    }
}
