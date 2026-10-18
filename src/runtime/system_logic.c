#include "open_secure_rom/system_closure.h"

#include "open_secure_rom/configuration_sink.h"
#include "open_secure_rom/crypto_hmac.h"
#include "open_secure_rom/der.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

enum {
    PROVISIONING_AUTHENTICATION_KEY_PRESENT_OFFSET = 88,
    PROVISIONING_AUTHENTICATION_KEY_OFFSET = 89,
    PROVISIONING_OPTIONAL_KEY_OFFSET = 121,
    PROVISIONING_OPTIONAL_SEED_OFFSET = 170,
};

sep_bool open_secure_rom_exception_stack_pointer_is_valid(
    sep_u64 stack_pointer
) {
    return (sep_bool)(
        (stack_pointer > 0x04024000 && stack_pointer <= 0x0402c000) ||
        (stack_pointer > 0x0402c000 && stack_pointer <= 0x04030000)
    );
}

void open_secure_rom_exception_panic_record_initialize(
    open_secure_rom_exception_panic_record_t *record,
    sep_u32 vector_kind,
    const sep_exception_frame_t *frame,
    sep_u64 platform_context,
    const sep_u8 event_log[64]
) {
    sep_memzero(record, sizeof(*record));
    record->vector_kind = vector_kind;
    record->exception_link_register = frame->exception_link_register;
    record->exception_syndrome = (sep_u32)frame->exception_syndrome;
    record->exception_class =
        ((sep_u32)frame->exception_syndrome) >> 26;
    record->instruction_specific_syndrome =
        ((sep_u32)frame->exception_syndrome) & 0x01ffffff;
    record->fault_address = frame->fault_address;
    record->stack_pointer = frame->stack_pointer;
    record->link_register = frame->link_register;
    record->saved_program_status = frame->saved_program_status;
    record->platform_context = platform_context;
    sep_memmove(record->event_log, event_log, sizeof(record->event_log));
}

open_secure_rom_shared_region_status_t
open_secure_rom_shared_region_copy_page_checked(
    sep_u64 source_address,
    void *destination,
    sep_size_t length,
    open_secure_rom_shared_region_reader_t reader,
    void *reader_context
) {
    if (length > OPEN_SECURE_ROM_SHARED_PAGE_SIZE) {
        return OPEN_SECURE_ROM_SHARED_REGION_PAGE_LENGTH;
    }
    if ((source_address & (OPEN_SECURE_ROM_SHARED_PAGE_SIZE - 1)) != 0) {
        return OPEN_SECURE_ROM_SHARED_REGION_SOURCE_ALIGNMENT;
    }
    if ((source_address >> 32) != 0) {
        return OPEN_SECURE_ROM_SHARED_REGION_SOURCE_RANGE;
    }
    if (reader == NULL ||
        !reader(reader_context, source_address, destination, length)) {
        return OPEN_SECURE_ROM_SHARED_REGION_READER_FAILURE;
    }
    return OPEN_SECURE_ROM_SHARED_REGION_OK;
}

open_secure_rom_shared_region_status_t
open_secure_rom_shared_region_load_image_checked(
    sep_u64 shared_region_base,
    void *destination,
    sep_size_t capacity,
    open_secure_rom_shared_region_reader_t reader,
    void *reader_context,
    sep_size_t *encoded_length
) {
    if ((capacity & (OPEN_SECURE_ROM_SHARED_PAGE_SIZE - 1)) != 0) {
        return OPEN_SECURE_ROM_SHARED_REGION_CAPACITY_ALIGNMENT;
    }
    if (capacity >= 0x20000001ULL) {
        return OPEN_SECURE_ROM_SHARED_REGION_CAPACITY_LIMIT;
    }

    open_secure_rom_shared_region_status_t status =
        open_secure_rom_shared_region_copy_page_checked(
            shared_region_base,
            destination,
            OPEN_SECURE_ROM_SHARED_PAGE_SIZE,
            reader,
            reader_context
        );
    if (status != OPEN_SECURE_ROM_SHARED_REGION_OK) {
        return status;
    }
    sep_size_t total = 0;
    if (!sep_der_sequence_encoded_length(
            destination,
            OPEN_SECURE_ROM_SHARED_PAGE_SIZE,
            &total
        )) {
        return OPEN_SECURE_ROM_SHARED_REGION_DER_LENGTH;
    }
    if (total > capacity) {
        return OPEN_SECURE_ROM_SHARED_REGION_ENCODED_TOO_LARGE;
    }
    if (total < OPEN_SECURE_ROM_SHARED_PAGE_SIZE) {
        return OPEN_SECURE_ROM_SHARED_REGION_ENCODED_TOO_SMALL;
    }

    for (sep_size_t offset = OPEN_SECURE_ROM_SHARED_PAGE_SIZE;
         offset < total;
         offset += OPEN_SECURE_ROM_SHARED_PAGE_SIZE) {
        if (shared_region_base > UINT64_MAX - offset ||
            (uintptr_t)destination > UINTPTR_MAX - offset) {
            return OPEN_SECURE_ROM_SHARED_REGION_ADDRESS_OVERFLOW;
        }
        const sep_size_t remaining = total - offset;
        const sep_size_t chunk = remaining < OPEN_SECURE_ROM_SHARED_PAGE_SIZE
            ? remaining
            : OPEN_SECURE_ROM_SHARED_PAGE_SIZE;
        status = open_secure_rom_shared_region_copy_page_checked(
            shared_region_base + offset,
            (sep_u8 *)destination + offset,
            chunk,
            reader,
            reader_context
        );
        if (status != OPEN_SECURE_ROM_SHARED_REGION_OK) {
            return status;
        }
    }
    sep_memzero((sep_u8 *)destination + total, capacity - total);
    *encoded_length = total;
    return OPEN_SECURE_ROM_SHARED_REGION_OK;
}

open_secure_rom_shared_region_status_t
open_secure_rom_shared_region_plan_payload(
    sep_u64 region_base,
    sep_size_t region_length,
    const sep_shared_image_context_t *image,
    open_secure_rom_shared_region_payload_plan_t *plan
) {
    const sep_u64 payload_source =
        (sep_u64)(uintptr_t)image->payload_data;
    if (payload_source < region_base ||
        image->payload_size > region_length) {
        return OPEN_SECURE_ROM_SHARED_REGION_ENCODED_TOO_LARGE;
    }

    sep_size_t payload_capacity = image->payload_size;
    const sep_size_t page_mask = OPEN_SECURE_ROM_SHARED_PAGE_SIZE - 1;
    if ((payload_capacity & page_mask) != 0) {
        if (payload_capacity > UINT64_MAX - page_mask) {
            return OPEN_SECURE_ROM_SHARED_REGION_ADDRESS_OVERFLOW;
        }
        payload_capacity = (payload_capacity + page_mask) & ~page_mask;
    }
    if (payload_capacity > region_length ||
        image->manifest_size > region_length - payload_capacity ||
        region_base > UINT64_MAX - payload_capacity) {
        return OPEN_SECURE_ROM_SHARED_REGION_ENCODED_TOO_LARGE;
    }

    plan->payload_destination = region_base;
    plan->payload_length = image->payload_size;
    plan->payload_capacity = payload_capacity;
    plan->manifest_destination = region_base + payload_capacity;
    plan->manifest_length = image->manifest_size;
    return OPEN_SECURE_ROM_SHARED_REGION_OK;
}

sep_bool open_secure_rom_provisioning_install_artm_from_payload(
    sep_platform_provisioning_state_t *state,
    const sep_u8 payload[32]
) {
    sep_u8 source[24];
    sep_u8 derived_key[32];
    sep_u8 message[17];
    sep_memzero(source, sizeof(source));
    sep_memmove(source + 8, payload, 16);
    sep_memzero(derived_key, sizeof(derived_key));
    sep_platform_key_material_transform_noop(
        "ARTM",
        source,
        sizeof(source),
        derived_key,
        sizeof(derived_key)
    );
    message[0] = 1;
    sep_memmove(message + 1, payload, 16);
    if (!sep_hmac_sha256_tag_matches(
            derived_key,
            message,
            sizeof(message),
            payload + 16,
            16
        )) {
        return 0;
    }
    sep_memmove(
        &state->bytes[PROVISIONING_AUTHENTICATION_KEY_OFFSET],
        derived_key,
        sizeof(derived_key)
    );
    state->bytes[PROVISIONING_AUTHENTICATION_KEY_PRESENT_OFFSET] = 1;
    return 1;
}

sep_bool open_secure_rom_provisioning_extract_research_from_payload(
    sep_platform_provisioning_state_t *state,
    const sep_u8 payload[86]
) {
    sep_u8 message[71];
    message[0] = 2;
    sep_memmove(message + 1, payload, 70);
    if (!sep_hmac_sha256_tag_matches(
            &state->bytes[PROVISIONING_AUTHENTICATION_KEY_OFFSET],
            message,
            sizeof(message),
            payload + 70,
            16
        )) {
        return 0;
    }

    sep_optional_configuration_key48_t key;
    sep_optional_research_seed_t seed;
    sep_memzero(&key, sizeof(key));
    sep_memzero(&seed, sizeof(seed));
    sep_size_t offset = 0;
    if (payload[offset] != 0) {
        if (payload[offset] != 1) {
            return 0;
        }
        sep_optional_configuration_key48_initialize_from_data(
            &key,
            payload + offset + 1,
            48
        );
        offset = 49;
    }
    if (payload[offset] != 0) {
        if (payload[offset] != 1) {
            return 0;
        }
        sep_optional_research_seed_initialize_from_data(
            &seed,
            payload + offset + 1,
            20
        );
    }
    sep_memmove(
        &state->bytes[PROVISIONING_OPTIONAL_KEY_OFFSET],
        &key,
        sizeof(key)
    );
    sep_memmove(
        &state->bytes[PROVISIONING_OPTIONAL_SEED_OFFSET],
        &seed,
        sizeof(seed)
    );
    return 1;
}

sep_u32 open_secure_rom_runtime_initialization_panic_reason(
    sep_u32 zero_result,
    sep_bool secondary_path_enabled,
    int initial_iteration_status,
    sep_u32 slot_count,
    const int *slot_statuses,
    sep_size_t status_count
) {
    if (zero_result != 0) {
        return 0x41;
    }
    if (!secondary_path_enabled) {
        return 0x47;
    }
    if (initial_iteration_status != 0) {
        return 0x4c;
    }
    for (sep_u32 slot = 1; slot < slot_count; ++slot) {
        if (slot - 1 >= status_count || slot_statuses[slot - 1] == 0) {
            return 0x50;
        }
    }
    return 0;
}
