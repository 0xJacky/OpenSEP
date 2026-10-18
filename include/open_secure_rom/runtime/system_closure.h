#ifndef OPEN_SECURE_ROM_SYSTEM_CLOSURE_H
#define OPEN_SECURE_ROM_SYSTEM_CLOSURE_H

#include "open_secure_rom/types.h"

enum {
    OPEN_SECURE_ROM_EXCEPTION_FRAME_SIZE = 56,
    OPEN_SECURE_ROM_EXCEPTION_PANIC_RECORD_SIZE = 416,
    OPEN_SECURE_ROM_SHARED_PAGE_SIZE = 0x4000,
};

typedef struct sep_exception_frame {
    sep_u64 frame_pointer;
    sep_u64 link_register;
    sep_u64 stack_pointer;
    sep_u32 saved_program_status;
    sep_u32 reserved;
    sep_u64 exception_link_register;
    sep_u64 fault_address;
    sep_u64 exception_syndrome;
} sep_exception_frame_t;

typedef void (*sep_exception_handler_t)(sep_exception_frame_t *frame);

typedef struct open_secure_rom_exception_panic_record {
    sep_u64 vector_kind;
    sep_u64 exception_link_register;
    sep_u64 exception_syndrome;
    sep_u64 exception_class;
    sep_u64 instruction_specific_syndrome;
    sep_u64 fault_address;
    sep_u64 stack_pointer;
    sep_u64 link_register;
    sep_u64 saved_program_status;
    sep_u64 reserved[3];
    sep_u64 platform_context;
    sep_u8 event_log[64];
    sep_u64 return_addresses[31];
} open_secure_rom_exception_panic_record_t;

typedef sep_bool (*open_secure_rom_shared_region_reader_t)(
    void *context,
    sep_u64 source_address,
    void *destination,
    sep_size_t length
);

typedef enum open_secure_rom_shared_region_status {
    OPEN_SECURE_ROM_SHARED_REGION_OK = 0,
    OPEN_SECURE_ROM_SHARED_REGION_PAGE_LENGTH,
    OPEN_SECURE_ROM_SHARED_REGION_SOURCE_ALIGNMENT,
    OPEN_SECURE_ROM_SHARED_REGION_SOURCE_RANGE,
    OPEN_SECURE_ROM_SHARED_REGION_READER_FAILURE,
    OPEN_SECURE_ROM_SHARED_REGION_CAPACITY_ALIGNMENT,
    OPEN_SECURE_ROM_SHARED_REGION_CAPACITY_LIMIT,
    OPEN_SECURE_ROM_SHARED_REGION_DER_LENGTH,
    OPEN_SECURE_ROM_SHARED_REGION_ENCODED_TOO_LARGE,
    OPEN_SECURE_ROM_SHARED_REGION_ENCODED_TOO_SMALL,
    OPEN_SECURE_ROM_SHARED_REGION_ADDRESS_OVERFLOW,
} open_secure_rom_shared_region_status_t;

typedef struct open_secure_rom_shared_region_payload_plan {
    sep_u64 payload_destination;
    sep_size_t payload_length;
    sep_size_t payload_capacity;
    sep_u64 manifest_destination;
    sep_size_t manifest_length;
} open_secure_rom_shared_region_payload_plan_t;

_Static_assert(
    sizeof(sep_exception_frame_t) == OPEN_SECURE_ROM_EXCEPTION_FRAME_SIZE,
    "exception frame ABI"
);
_Static_assert(
    offsetof(sep_exception_frame_t, saved_program_status) == 24,
    "exception frame SPSR offset"
);
_Static_assert(
    offsetof(sep_exception_frame_t, exception_link_register) == 32,
    "exception frame ELR offset"
);
_Static_assert(
    offsetof(sep_exception_frame_t, exception_syndrome) == 48,
    "exception frame ESR offset"
);
_Static_assert(
    sizeof(open_secure_rom_exception_panic_record_t) ==
        OPEN_SECURE_ROM_EXCEPTION_PANIC_RECORD_SIZE,
    "exception panic record ABI"
);
_Static_assert(
    offsetof(open_secure_rom_exception_panic_record_t, event_log) == 104,
    "exception panic event log offset"
);
_Static_assert(
    offsetof(open_secure_rom_exception_panic_record_t, return_addresses) == 168,
    "exception panic return-address offset"
);

sep_bool open_secure_rom_exception_stack_pointer_is_valid(
    sep_u64 stack_pointer
);
void open_secure_rom_exception_panic_record_initialize(
    open_secure_rom_exception_panic_record_t *record,
    sep_u32 vector_kind,
    const sep_exception_frame_t *frame,
    sep_u64 platform_context,
    const sep_u8 event_log[64]
);

open_secure_rom_shared_region_status_t
open_secure_rom_shared_region_copy_page_checked(
    sep_u64 source_address,
    void *destination,
    sep_size_t length,
    open_secure_rom_shared_region_reader_t reader,
    void *reader_context
);
open_secure_rom_shared_region_status_t
open_secure_rom_shared_region_load_image_checked(
    sep_u64 shared_region_base,
    void *destination,
    sep_size_t capacity,
    open_secure_rom_shared_region_reader_t reader,
    void *reader_context,
    sep_size_t *encoded_length
);
open_secure_rom_shared_region_status_t
open_secure_rom_shared_region_plan_payload(
    sep_u64 region_base,
    sep_size_t region_length,
    const sep_shared_image_context_t *image,
    open_secure_rom_shared_region_payload_plan_t *plan
);

sep_bool open_secure_rom_provisioning_install_artm_from_payload(
    sep_platform_provisioning_state_t *state,
    const sep_u8 payload[32]
);
sep_bool open_secure_rom_provisioning_extract_research_from_payload(
    sep_platform_provisioning_state_t *state,
    const sep_u8 payload[86]
);
sep_u32 open_secure_rom_runtime_initialization_panic_reason(
    sep_u32 zero_result,
    sep_bool secondary_path_enabled,
    int initial_iteration_status,
    sep_u32 slot_count,
    const int *slot_statuses,
    sep_size_t status_count
);

void __attribute__((noreturn))
sep_boot_scrub_architectural_state_and_enter_runtime(
    sep_u64 first,
    sep_u64 second,
    sep_u64 entry,
    sep_u64 power_down_save
);
void __attribute__((noreturn)) sep_boot_prepare_and_transfer_runtime(
    const sep_shared_image_context_t *image,
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
);
void __attribute__((noreturn)) sep_runtime_set_stacks_and_enter(void);
void sep_exception_validate_stack_pointer(void);
void __attribute__((noreturn)) sep_exception_current_el_sp0_sync(void);
void __attribute__((noreturn)) sep_exception_current_el_sp0_irq(void);
void __attribute__((noreturn)) sep_exception_current_el_sp0_fiq(void);
void __attribute__((noreturn)) sep_exception_current_el_sp0_serror(void);
void __attribute__((noreturn)) sep_exception_dispatch(
    sep_exception_frame_t *frame,
    sep_exception_handler_t handler
);
void __attribute__((noreturn)) sep_exception_handle_sync(
    sep_exception_frame_t *frame
);
void sep_exception_build_panic_record(
    sep_u32 vector_kind,
    const sep_exception_frame_t *frame
);
void __attribute__((noreturn)) sep_exception_handle_serror(
    sep_exception_frame_t *frame
);
void sep_shared_region_copy_page(
    sep_u64 source_address,
    void *destination,
    sep_size_t length
);
void sep_shared_region_load_image(
    sep_u64 shared_region_base,
    void *destination,
    sep_size_t capacity
);
void __attribute__((noreturn)) sep_shared_region_import_and_commit(
    sep_u64 shared_region_base,
    sep_u8 mode
);
sep_bool sep_platform_provisioning_install_artm_authentication_key(
    sep_platform_provisioning_state_t *state,
    sep_size_t record_index
);
sep_bool sep_platform_provisioning_extract_research_values(
    sep_platform_provisioning_state_t *state,
    sep_size_t record_index
);
void __attribute__((noreturn)) sep_runtime_initialize_regions_and_transfer(
    void
);

#endif
