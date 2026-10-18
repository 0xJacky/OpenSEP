#ifndef OPEN_SECURE_ROM_AKE_H
#define OPEN_SECURE_ROM_AKE_H

#include "open_secure_rom/ecc.h"

typedef sep_u8 sep_ake_transport_command_t;

enum {
    SEP_AKE_SESSION_CAPACITY = 5,
    SEP_AKE_RECORD_SIZE = 64,
    SEP_AKE_RECORD_COUNT = 69,
};

typedef struct sep_ake_message_prefix {
    sep_u8 command;
    sep_u8 key_slot;
    sep_u8 data_slot;
    sep_u8 flags;
} sep_ake_message_prefix_t;

typedef struct sep_ake_session_slot {
    sep_u8 valid;
    sep_u8 key_slot;
    sep_u8 reserved[2];
    sep_u32 counter;
    sep_u8 nonce_seed[8];
    sep_u8 request_key[32];
    sep_u8 response_key[32];
} sep_ake_session_slot_t;

typedef struct sep_ake_mode_capabilities {
    sep_u8 session_capacity;
    sep_u8 maximum_key_slot;
    sep_u8 special_slot_selector;
} sep_ake_mode_capabilities_t;

typedef struct sep_ake_transport_failure_record {
    sep_u8 bytes[68];
} sep_ake_transport_failure_record_t;

typedef struct sep_ake_context {
    sep_u8 private_prefix[100];
    sep_ake_session_slot_t sessions[SEP_AKE_SESSION_CAPACITY];
    sep_u32 transport_mode;
    sep_u8 active_command;
    sep_u8 private_505[7];
    const void *transport_status_token;
    sep_u8 transport_failed;
    sep_u8 retry_transport;
    sep_u8 private_522[6];
    const sep_u8 *connect_cmac_key;
    sep_ake_session_slot_t *active_session;
    sep_u8 *record_output;
    sep_u8 mode5_record_count;
    sep_u8 private_553[7];
    const sep_u8 *mode5_record_order;
    sep_u8 *metadata_output;
    sep_u8 failure_in_progress;
    sep_u8 transport_id;
    sep_u8 allow_status_e0;
    sep_u8 private_tail;
} sep_ake_context_t;

typedef sep_bool (*sep_ake_transport_exchange_fn)(
    sep_u8 transport_id,
    const sep_u8 *request,
    sep_size_t request_size,
    sep_u8 *response,
    sep_size_t response_size,
    sep_bool retry,
    void *opaque
);

void open_secure_rom_ake_context_initialize(
    sep_ake_context_t *context,
    sep_u32 mode,
    sep_u8 transport_id
);
void open_secure_rom_ake_set_transport_exchange(
    sep_ake_transport_exchange_fn exchange,
    void *opaque
);
void open_secure_rom_ake_record_service_load_record(
    sep_u8 record_index,
    const sep_u8 record[SEP_AKE_RECORD_SIZE]
);

sep_bool sep_ake_transport_exchange_status_stub(
    sep_u8 transport_id,
    const void *request,
    void *response,
    sep_bool retry
);
sep_bool sep_ake_validate_transport_provider(
    sep_u8 transport_id,
    const void *request,
    const void *response
);
void sep_ake_cache_transport_failure_record_if_reserved_zero(
    const void *site_tag,
    const sep_ake_transport_failure_record_t *record
);
sep_ccrng_state_t *sep_ake_get_zero_rng_state(void);
void sep_ake_normalize_record_service_key_source(
    sep_u8 output[32],
    sep_size_t output_size,
    const void *source,
    sep_size_t source_size
);
sep_bool sep_ake_buffer_has_nonzero_byte(
    const void *buffer,
    sep_size_t length
);
void sep_ake_initialize_record_service_keys(void);
sep_bool sep_ake_select_record(sep_u8 record_index);
void sep_ake_cache_record_metadata(sep_u8 record_index);
sep_bool sep_ake_find_authenticated_record(
    sep_u16 record_selector,
    sep_u8 *output
);
void sep_ake_close_record_service(void);
sep_bool sep_ake_record_service_is_closed(void);
sep_ake_transport_failure_record_t
sep_ake_get_cached_transport_failure_record(void);
sep_bool sep_ake_prepare_type9_record_table(sep_u8 subtype);
sep_u32 sep_ake_read_prepared_table_word(sep_size_t byte_offset);
int sep_ake_zero_rng_generate(
    sep_ccrng_state_t *rng,
    sep_size_t output_length,
    void *output
);

sep_u32 sep_ake_resolve_command_timeout_us(
    const sep_ake_context_t *context,
    const sep_ake_message_prefix_t *request,
    sep_bool use_extended_limit
);
sep_u32 sep_ake_timeout_for_transport_mode1(
    sep_ake_transport_command_t command,
    sep_bool use_extended_limit
);
sep_u32 sep_ake_timeout_for_transport_modes_0_3_4(
    const sep_ake_message_prefix_t *request,
    sep_bool use_extended_limit
);
sep_u32 sep_ake_timeout_for_transport_mode5(
    const sep_ake_message_prefix_t *request,
    sep_bool use_extended_limit
);
const sep_ake_mode_capabilities_t *sep_ake_get_mode_capabilities(
    const sep_ake_context_t *context
);
sep_ake_session_slot_t *sep_ake_find_session_slot(
    sep_ake_context_t *context,
    sep_u8 key_slot
);
void sep_ake_execute_transport_command(
    sep_ake_context_t *context,
    const sep_u8 *request,
    sep_size_t request_size,
    sep_u8 *response,
    sep_size_t response_size
);
void sep_ake_derive_session_material_from_p384_ecdh(
    sep_u8 *output,
    const void *local_private_key,
    const sep_u8 *peer_public_key,
    const sep_u8 *extractor_key,
    const sep_u8 *context,
    const sep_u8 *label,
    void *rng_state
);
sep_bool sep_ake_kbkdf_cmac_derive(
    const sep_u8 *cmac_key,
    const sep_u8 *label,
    const sep_u8 *context,
    sep_u8 *output,
    sep_size_t output_size
);
sep_bool sep_ake_verify_connect_response_cmac(
    const sep_u8 *expected_cmac,
    const sep_u8 *key,
    const sep_ake_message_prefix_t *prefix,
    const sep_u8 *request_public_key,
    const sep_u8 *response_public_key
);
sep_bool sep_ake_ccm_decrypt_and_verify_response(
    const sep_ake_session_slot_t *slot,
    const sep_ake_message_prefix_t *prefix,
    const void *ciphertext,
    sep_size_t ciphertext_length,
    const sep_u8 *tag,
    void *plaintext
);
sep_u8 sep_ake_get_transport_status(const sep_ake_context_t *context);
void sep_ake_build_ccm_nonce(
    const sep_ake_session_slot_t *slot,
    sep_u8 *nonce
);
void sep_ake_build_ccm_aad(
    const sep_ake_session_slot_t *slot,
    const sep_ake_message_prefix_t *prefix,
    sep_u8 *aad
);
sep_ake_session_slot_t *sep_ake_require_session_slot_for_authenticated_request(
    sep_ake_context_t *context,
    sep_u8 key_slot
);
void sep_ake_ccm_authenticate_empty_request_and_advance_counter(
    sep_ake_session_slot_t *slot,
    const sep_ake_message_prefix_t *prefix,
    sep_u8 *tag
);
sep_bool sep_ake_connect_key_slot(
    sep_ake_context_t *context,
    sep_u8 key_slot,
    const sep_u8 *key_material,
    sep_size_t key_material_length
);
void sep_ake_compute_connect_request_cmac(
    sep_u8 *output,
    const sep_u8 *key,
    const sep_ake_message_prefix_t *prefix,
    const sep_u8 *public_key
);
void sep_ake_disconnect_key_slot(sep_ake_context_t *context, sep_u8 key_slot);
void sep_ake_read_authenticated_record(
    sep_ake_context_t *context,
    sep_u8 key_slot,
    sep_u8 request_flags,
    sep_u8 *output
);
void sep_ake_read_record_metadata(
    sep_ake_context_t *context,
    sep_u8 key_slot,
    sep_u8 data_slot,
    sep_u8 request_flags,
    sep_u8 *output,
    sep_size_t output_size
);
void sep_ake_finalize_transport(sep_ake_context_t *context);
sep_bool sep_ake_verify_record_crc16(const sep_u8 *record);
void __attribute__((noreturn)) sep_ake_verify_record_crc16_null_assert(void);
void sep_ake_compute_record_types_1_2_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
);
void sep_ake_compute_record_type_3_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
);
void sep_ake_compute_record_types_4_6_and_10_25_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
);
void sep_ake_compute_record_types_7_8_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
);
void sep_ake_compute_record_type_9_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_u8 *authenticator
);
sep_bool sep_ake_verify_record_authenticator(
    const sep_u8 *record,
    const sep_u8 *authentication_key,
    sep_size_t authentication_key_size
);
void sep_ake_derive_record_service_keys(
    sep_u8 *sp_key,
    sep_size_t sp_key_size,
    sep_u8 *counter_block_mac_key,
    sep_size_t counter_block_mac_key_size,
    const void *source,
    sep_size_t source_size
);
void __attribute__((noreturn)) sep_ake_handle_transport_failure(
    sep_ake_context_t *context
);

#endif
