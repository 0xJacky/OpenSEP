#include "open_secure_rom/shared_image.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

static void require_properties(
    const sep_shared_image_properties_t *properties
) {
    if (properties == 0 || ((uintptr_t)properties & 7) != 0) {
        sep_fatal_wait_loop();
    }
}

static void store_checked48(
    sep_shared_image_properties_t *properties,
    sep_size_t presence_offset,
    const sep_checked_bytes48_t *digest
) {
    properties->bytes[presence_offset] = 1;
    sep_memmove(
        &properties->bytes[presence_offset + 1],
        digest,
        sizeof(*digest)
    );
}

static sep_bool checked_flag(
    const sep_shared_image_properties_t *properties,
    sep_size_t offset
) {
    require_properties(properties);
    const sep_bool value = properties->bytes[offset];
    if (value >= 2) {
        sep_fatal_wait_loop();
    }
    return value;
}

static sep_u16 load_u16(const sep_u8 *bytes) {
    sep_u16 value;
    sep_memmove(&value, bytes, sizeof(value));
    return value;
}

static sep_u64 load_u64(const sep_u8 *bytes) {
    sep_u64 value;
    sep_memmove(&value, bytes, sizeof(value));
    return value;
}

void sep_shared_image_properties_initialize(
    sep_shared_image_properties_t *properties
) {
    sep_shared_image_properties_initialize_fields(properties);
}

void sep_shared_image_properties_initialize_fields(
    sep_shared_image_properties_t *properties
) {
    require_properties(properties);
    properties->bytes[0] = 2;
    sep_memzero(&properties->bytes[1], 7);
    sep_optional_u16_initialize_absent(
        (sep_optional_u16_t *)&properties->bytes[10]
    );
    sep_optional_u64_initialize_absent(
        (sep_optional_u64_t *)&properties->bytes[16]
    );
    sep_optional_u64_initialize_absent(
        (sep_optional_u64_t *)&properties->bytes[32]
    );
    sep_memzero(&properties->bytes[48], 0xc3);
}

void sep_shared_image_properties_set_manifest_digest(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *digest
) {
    require_properties(properties);
    store_checked48(properties, 56, digest);
}

void sep_shared_image_properties_set_cepo(
    sep_shared_image_properties_t *properties,
    sep_u64 value
) {
    require_properties(properties);
    sep_optional_u8_initialize_from_u64(
        (sep_optional_u8_t *)&properties->bytes[8],
        &value
    );
}

void sep_shared_image_properties_set_chip(
    sep_shared_image_properties_t *properties,
    sep_u64 value
) {
    require_properties(properties);
    sep_optional_u16_initialize_from_u64(
        (sep_optional_u16_t *)&properties->bytes[10],
        &value
    );
}

void sep_shared_image_properties_set_ecid(
    sep_shared_image_properties_t *properties,
    sep_u64 value
) {
    require_properties(properties);
    sep_optional_u64_initialize_from_u64(
        (sep_optional_u64_t *)&properties->bytes[16],
        &value
    );
}

void sep_shared_image_properties_set_bord(
    sep_shared_image_properties_t *properties,
    sep_u64 value
) {
    require_properties(properties);
    sep_optional_u64_initialize_from_u64(
        (sep_optional_u64_t *)&properties->bytes[32],
        &value
    );
}

void sep_shared_image_properties_set_sdom(
    sep_shared_image_properties_t *properties,
    sep_u64 value
) {
    require_properties(properties);
    sep_optional_u8_initialize_from_u64(
        (sep_optional_u8_t *)&properties->bytes[48],
        &value
    );
}

void sep_shared_image_properties_set_cpro(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    sep_optional_bool_initialize_from_bool(
        (sep_optional_bool_t *)&properties->bytes[50],
        &value
    );
}

void sep_shared_image_properties_set_csec(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    sep_optional_bool_initialize_from_bool(
        (sep_optional_bool_t *)&properties->bytes[52],
        &value
    );
}

void sep_shared_image_properties_set_uidm(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    sep_optional_bool_initialize_from_bool(
        (sep_optional_bool_t *)&properties->bytes[54],
        &value
    );
}

void sep_shared_image_properties_set_ekey(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    properties->bytes[234] = value;
}

void sep_shared_image_properties_set_eg0t(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    properties->bytes[235] = value;
}

void sep_shared_image_properties_set_eg1t(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    properties->bytes[236] = value;
}

void sep_shared_image_properties_set_eg3t(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    properties->bytes[237] = value;
}

void sep_shared_image_properties_set_eg0n(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    properties->bytes[238] = value;
}

void sep_shared_image_properties_set_eg1n(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    properties->bytes[239] = value;
}

void sep_shared_image_properties_set_eg3n(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    properties->bytes[240] = value;
}

void sep_shared_image_properties_set_dgst(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *digest
) {
    require_properties(properties);
    store_checked48(properties, 106, digest);
}

void sep_shared_image_properties_set_oppd(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *digest
) {
    require_properties(properties);
    store_checked48(properties, 156, digest);
}

void sep_shared_image_properties_set_snon(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes20_t *nonce
) {
    require_properties(properties);
    properties->bytes[206] = 1;
    sep_memmove(&properties->bytes[207], nonce, sizeof(*nonce));
}

void sep_shared_image_properties_mark_amnm(
    sep_shared_image_properties_t *properties
) {
    require_properties(properties);
    properties->bytes[241] = 1;
}

void sep_shared_image_properties_mark_dsec(
    sep_shared_image_properties_t *properties
) {
    require_properties(properties);
    properties->bytes[242] = 1;
}

void sep_shared_image_properties_set_epro(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    sep_optional_bool_initialize_from_bool(
        (sep_optional_bool_t *)&properties->bytes[228],
        &value
    );
}

void sep_shared_image_properties_set_esec(
    sep_shared_image_properties_t *properties,
    sep_bool value
) {
    require_properties(properties);
    sep_optional_bool_initialize_from_bool(
        (sep_optional_bool_t *)&properties->bytes[230],
        &value
    );
}

void sep_shared_image_properties_set_esdm(
    sep_shared_image_properties_t *properties,
    sep_u8 value
) {
    require_properties(properties);
    properties->bytes[232] = 1;
    properties->bytes[233] = value;
}

sep_bool sep_shared_image_properties_ekey_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 234);
}

sep_bool sep_shared_image_properties_eg0t_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 235);
}

sep_bool sep_shared_image_properties_eg1t_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 236);
}

sep_bool sep_shared_image_properties_eg3t_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 237);
}

sep_bool sep_shared_image_properties_eg0n_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 238);
}

sep_bool sep_shared_image_properties_eg1n_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 239);
}

sep_bool sep_shared_image_properties_eg3n_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 240);
}

sep_bool sep_shared_image_properties_amnm_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 241);
}

sep_bool sep_shared_image_properties_dsec_checked(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 242);
}

sep_bool sep_shared_image_properties_has_oppd(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 156);
}

sep_bool sep_shared_image_properties_has_dgst(
    const sep_shared_image_properties_t *properties
) {
    return checked_flag(properties, 106);
}

sep_bool sep_shared_image_properties_oppd_matches_if_present(
    const sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *expected
) {
    if (!sep_shared_image_properties_has_oppd(properties)) {
        return 1;
    }
    return sep_checked_bytes48_equal(
        (const sep_checked_bytes48_t *)&properties->bytes[157],
        expected
    );
}

sep_bool sep_shared_image_properties_dgst_matches_if_present(
    const sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *expected
) {
    if (!sep_shared_image_properties_has_dgst(properties)) {
        return 1;
    }
    return sep_checked_bytes48_equal(
        (const sep_checked_bytes48_t *)&properties->bytes[107],
        expected
    );
}

sep_bool sep_shared_image_validate_platform_constraints(
    const sep_shared_image_context_t *context
) {
    if (context == 0 || ((uintptr_t)context & 7) != 0) {
        sep_fatal_wait_loop();
    }
    const sep_u8 *properties = context->decoded_properties;
    sep_bool valid = 1;

    if (properties[8] >= 2) {
        sep_fatal_wait_loop();
    }
    if (properties[8] &&
        properties[9] < sep_platform_get_security_epoch()) {
        sep_protocol_event_log_append(0x4003000b);
        valid = 0;
    }
    if (properties[10] >= 2) {
        sep_fatal_wait_loop();
    }
    if (properties[10] &&
        load_u16(&properties[12]) != sep_platform_get_chip_id()) {
        sep_protocol_event_log_append(0x40030008);
        valid = 0;
    }
    if (properties[16] >= 2) {
        sep_fatal_wait_loop();
    }
    if (properties[16] &&
        load_u64(&properties[24]) != sep_platform_read_ecid()) {
        sep_protocol_event_log_append(0x40030007);
        valid = 1;
    }
    if (properties[32] >= 2) {
        sep_fatal_wait_loop();
    }
    if (properties[32] &&
        load_u64(&properties[40]) != sep_platform_read_chip_revision()) {
        sep_protocol_event_log_append(0x40030009);
        valid = 0;
    }

    valid &= sep_optional_u8_matches_or_log(
        load_u16(&properties[48]),
        (sep_u16)sep_platform_read_security_domain_encoded(),
        0x40030012,
        0x4003000a
    );
    valid &= sep_optional_bool_matches_or_log(
        load_u16(&properties[50]),
        (sep_u16)sep_platform_read_flag_08_encoded(),
        0x40030013,
        0x4003000c
    );
    valid &= sep_optional_bool_matches_or_log(
        load_u16(&properties[52]),
        (sep_u16)sep_platform_read_flag_0c_encoded(),
        0x40030014,
        0x4003000d
    );
    const sep_optional_u8_t default_esdm = sep_optional_u8_initialize_absent();
    valid &= sep_optional_u8_matches_or_log(
        load_u16(&properties[232]),
        load_u16((const sep_u8 *)&default_esdm),
        0x4003001b,
        0x4003001a
    );

    if (properties[54] >= 2 || properties[242] >= 2) {
        sep_fatal_wait_loop();
    }
    if (properties[54]) {
        if (properties[55] >= 2) {
            sep_fatal_wait_loop();
        }
        if (properties[55] != sep_platform_zero_result_stub()) {
            sep_protocol_event_log_append(0x4003000e);
            valid = 0;
        }
    }
    valid &= sep_optional_bool_matches_or_log(
        load_u16(&properties[230]),
        (sep_u16)sep_platform_read_flag_0c_boolean_encoded(),
        0x40030015,
        0x4003000f
    );
    return valid;
}
