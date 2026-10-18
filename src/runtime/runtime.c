#include "open_secure_rom/runtime.h"

void *sep_memzero(void *destination, sep_size_t length) {
#ifndef OPEN_SECURE_ROM_HOST_TEST
    /* Multi-megabyte runtime apertures must meet the SEP boot ACK deadline. */
    if (length >= 0x4000) {
        const uintptr_t end = (uintptr_t)destination + length;
        uintptr_t cursor = (uintptr_t)destination;
        const uintptr_t aligned = (cursor + 63) & ~(uintptr_t)63;
        while (cursor < aligned) {
            *(volatile sep_u8 *)cursor++ = 0;
        }
        while (cursor + 64 <= end) {
            __asm__ volatile("dc zva, %0" :: "r"(cursor) : "memory");
            cursor += 64;
        }
        while (cursor < end) {
            *(volatile sep_u8 *)cursor++ = 0;
        }
        return destination;
    }
#endif
    return sep_memset(destination, 0, length);
}

void *sep_memset(void *destination, int value, sep_size_t length) {
    sep_u8 *bytes = destination;
    for (sep_size_t index = 0; index < length; ++index) {
        bytes[index] = (sep_u8)value;
    }
    return destination;
}

void *sep_memmove(void *destination, const void *source, sep_size_t length) {
    sep_u8 *output = destination;
    const sep_u8 *input = source;
    if (output < input) {
        for (sep_size_t index = 0; index < length; ++index) {
            output[index] = input[index];
        }
    } else if (output > input) {
        for (sep_size_t index = length; index != 0; --index) {
            output[index - 1] = input[index - 1];
        }
    }
    return destination;
}

/** LLVM lowers large freestanding structure returns to this C ABI symbol. */
void *memcpy(void *destination, const void *source, sep_size_t length) {
    sep_u8 *output = destination;
    const sep_u8 *input = source;
    for (sep_size_t index = 0; index < length; ++index) {
        output[index] = input[index];
    }
    return destination;
}

sep_bool sep_buffer_has_nonzero_byte(const void *buffer, sep_size_t length) {
    const sep_u8 *bytes = buffer;
    sep_u8 combined = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        combined |= bytes[index];
    }
    return combined != 0;
}

int sep_constant_time_memcmp(const void *left, const void *right, sep_size_t length) {
    const sep_u8 *left_bytes = left;
    const sep_u8 *right_bytes = right;
    int result = 0;
    sep_u32 found_difference = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        const int difference = (int)left_bytes[index] - (int)right_bytes[index];
        const sep_u32 unsigned_difference = (sep_u32)difference;
        const sep_u32 is_different =
            (unsigned_difference | (sep_u32)(0U - unsigned_difference)) >> 31;
        const sep_u32 take = is_different & (found_difference ^ 1U);
        const int mask = -(int)take;
        result = (result & ~mask) | (difference & mask);
        found_difference |= is_different;
    }
    return result;
}

int sep_constant_time_memcmp_veneer(
    const void *left,
    const void *right,
    sep_size_t length
) {
    return sep_constant_time_memcmp(left, right, length);
}

int sep_memset_checked(
    void *destination,
    sep_size_t destination_size,
    int value,
    sep_size_t count,
    sep_size_t object_size
) {
    if (count > destination_size || destination_size > object_size) {
        sep_fatal_wait_loop();
    }
    sep_memset(destination, value, count);
    return 0;
}

void *sep_memmove_checked(
    void *destination,
    const void *source,
    sep_size_t length,
    sep_size_t destination_size
) {
    if (length > destination_size) {
        sep_fatal_wait_loop();
    }
    return sep_memmove(destination, source, length);
}

void *sep_memmove_qwords(
    sep_size_t qword_count,
    void *destination,
    const void *source
) {
    return sep_memmove(destination, source, qword_count * sizeof(sep_u64));
}

void *sep_memzero_via_runtime(sep_size_t length, void *destination) {
    return sep_memset(destination, 0, length);
}

#ifndef OPEN_SECURE_ROM_HOST_TEST
void sep_wait_for_event_once_synchronized(void) {
    __asm__ volatile("dsb sy\n\tisb\n\twfe" ::: "memory");
}

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    for (;;) {
        __asm__ volatile("wfe" ::: "memory");
    }
}
#endif
