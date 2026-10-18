#include "open_secure_rom/runtime.h"

sep_u64 sep_xorshift64_state;

sep_u64 sep_xorshift64_next(void) {
    sep_u64 value = sep_xorshift64_state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    sep_xorshift64_state = value;
    return value;
}
