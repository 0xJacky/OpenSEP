#include "open_secure_rom/img4.h"

#include "open_secure_rom/event_log.h"
#include "open_secure_rom/panic.h"

static sep_u64 constraint_load_le64(const sep_u8 *bytes) {
    sep_u64 value = 0;
    for (sep_size_t index = 0; index < 8; ++index) {
        value |= (sep_u64)bytes[index] << (8 * index);
    }
    return value;
}

static sep_u32 constraint_load_u32(sep_u64 address) {
    const volatile sep_u32 *value = (const volatile sep_u32 *)(uintptr_t)address;
    return *value;
}

static sep_u64 constraint_load_u64(sep_u64 address) {
    const volatile sep_u64 *value = (const volatile sep_u64 *)(uintptr_t)address;
    return *value;
}

void sep_img4_constraint_record_decode(
    sep_img4_constraint_record_t *decoded,
    const sep_u8 raw_record[24]
) {
    if (decoded == NULL || raw_record == NULL ||
        ((uintptr_t)decoded & 7U) != 0) {
        sep_panic_reason_1a();
    }
    const sep_u64 header = constraint_load_le64(raw_record);
    decoded->value_source = (sep_u8)(header >> 62);
    decoded->comparison = (sep_u8)((header >> 60) & 3U);
    decoded->value_address = header & UINT64_C(0x0fffffffffffffff);
    decoded->mask = constraint_load_le64(raw_record + 8);
    decoded->reserved1 = constraint_load_le64(raw_record + 16);
}

void sep_img4_constraint_record_decode_checked(
    sep_img4_constraint_record_t *decoded,
    const sep_u8 raw_record[24]
) {
    sep_img4_constraint_record_decode(decoded, raw_record);
}

sep_bool sep_img4_constraint_record_evaluate(
    const sep_img4_constraint_record_t *record
) {
    if (record == NULL || ((uintptr_t)record & 7U) != 0) {
        sep_panic_reason_1a();
    }

    sep_u64 candidate;
    switch (record->value_source) {
    case 0:
        candidate = constraint_load_u32(record->value_address);
        break;
    case 1:
        candidate = constraint_load_u64(record->value_address);
        break;
    case 2: {
        if (record->value_address == 0 ||
            (record->value_address & 3U) != 0 ||
            record->value_address > UINT64_MAX - 4) {
            sep_panic_reason_1a();
        }
        const sep_u64 low = constraint_load_u32(record->value_address);
        const sep_u64 high = constraint_load_u32(record->value_address + 4);
        candidate = low | (high << 32);
        break;
    }
    case 3: {
        if (record->value_address == 0 ||
            (record->value_address & 3U) != 0 ||
            record->value_address > UINT64_MAX - 4) {
            sep_panic_reason_1a();
        }
        const sep_u64 high = constraint_load_u32(record->value_address);
        const sep_u64 low = constraint_load_u32(record->value_address + 4);
        candidate = low | (high << 32);
        break;
    }
    default:
        sep_panic_with_reason_and_pc(0xa7, 0);
    }

    candidate &= record->mask;
    switch (record->comparison) {
    case 0:
        return candidate == record->reserved1;
    case 1:
        return candidate != record->reserved1;
    case 2:
        return candidate < record->reserved1;
    case 3:
        return candidate > record->reserved1;
    default:
        sep_panic_with_reason_and_pc(0xc2, 0);
    }
}

sep_bool sep_img4_constraints_evaluate(
    const sep_u8 *records,
    sep_size_t records_length
) {
    if (records_length % 24 != 0) {
        sep_panic_with_reason_and_pc(0x46, 0);
    }
    if ((records_length >> 35) > 2) {
        sep_panic_reason_2a();
    }

    sep_bool valid = 1;
    for (sep_size_t offset = 0; offset < records_length; offset += 24) {
        sep_img4_constraint_record_t record = {0};
        sep_img4_constraint_record_decode_checked(&record, records + offset);
        if (!sep_img4_constraint_record_evaluate(&record)) {
            sep_protocol_diagnostic_record_write(
                0x40030026,
                records + offset,
                24
            );
            valid = 0;
        }
    }
    return valid;
}
