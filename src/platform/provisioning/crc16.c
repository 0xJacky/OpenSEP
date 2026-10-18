#include "open_secure_rom/provisioning.h"

#include "open_secure_rom/runtime.h"

sep_u16 sep_crc16_update(
    const void *data,
    sep_size_t length,
    sep_u16 crc
) {
    if (data == 0 && length != 0) {
        sep_fatal_wait_loop();
    }
    const sep_u8 *bytes = data;
    for (sep_size_t index = 0; index < length; ++index) {
        crc ^= (sep_u16)bytes[index] << 8;
        for (sep_u32 bit = 0; bit < 8; ++bit) {
            crc = (sep_u16)((crc & 0x8000) != 0
                ? (crc << 1) ^ 0x1021
                : crc << 1);
        }
    }
    return crc;
}
