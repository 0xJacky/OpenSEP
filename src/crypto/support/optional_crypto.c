#include "open_secure_rom/optional_values.h"

#include "open_secure_rom/crypto_digest.h"
#include "open_secure_rom/runtime.h"

sep_optional_configuration_key48_t
sep_optional_configuration_key48_from_sha384(
    const void *data,
    sep_size_t length
) {
    sep_optional_configuration_key48_t result;
    sep_memzero(&result, sizeof(result));
    sep_digest_by_bit_length(
        384,
        data,
        length,
        result.bytes,
        sizeof(result.bytes)
    );
    result.present = 1;
    return result;
}
