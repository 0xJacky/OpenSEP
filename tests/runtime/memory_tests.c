#include "open_secure_rom/runtime.h"

#include <assert.h>
#include <string.h>

extern sep_u64 sep_xorshift64_state;

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

int main(void) {
    sep_u8 bytes[16];
    sep_memset(bytes, 0xa5, sizeof(bytes));
    for (sep_size_t index = 0; index < sizeof(bytes); ++index) {
        assert(bytes[index] == 0xa5);
    }
    assert(sep_buffer_has_nonzero_byte(bytes, sizeof(bytes)) == 1);
    sep_memzero(bytes, sizeof(bytes));
    assert(sep_buffer_has_nonzero_byte(bytes, sizeof(bytes)) == 0);

    const char source[] = "0123456789";
    char overlapping[sizeof(source)];
    memcpy(overlapping, source, sizeof(source));
    sep_memmove(overlapping + 2, overlapping, 8);
    assert(memcmp(overlapping, "0101234567", 10) == 0);
    assert(sep_constant_time_memcmp(source, source, sizeof(source)) == 0);
    assert(sep_constant_time_memcmp(source, overlapping, sizeof(source)) == 2);
    assert(sep_constant_time_memcmp_veneer("b", "a", 1) == 1);

    sep_memset_checked(bytes, sizeof(bytes), 0x3c, 8, sizeof(bytes));
    assert(bytes[0] == 0x3c && bytes[7] == 0x3c && bytes[8] == 0);
    sep_memmove_checked(bytes + 8, bytes, 8, 8);
    assert(memcmp(bytes, bytes + 8, 8) == 0);
    sep_memzero_via_runtime(sizeof(bytes), bytes);
    assert(sep_buffer_has_nonzero_byte(bytes, sizeof(bytes)) == 0);

    sep_u64 qwords[4] = {1, 2, 3, 4};
    sep_memmove_qwords(3, qwords + 1, qwords);
    assert(qwords[0] == 1 && qwords[1] == 1 && qwords[2] == 2 && qwords[3] == 3);

    sep_xorshift64_state = 0x0123456789abcdefULL;
    assert(sep_xorshift64_next() == 0x3f2800d6569e01b4ULL);
}
