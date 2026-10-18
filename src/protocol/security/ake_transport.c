#include "open_secure_rom/ake.h"

#include "open_secure_rom/runtime.h"

sep_bool open_secure_rom_ake_exchange(
    sep_u8 transport_id,
    const sep_u8 *request,
    sep_size_t request_size,
    sep_u8 *response,
    sep_size_t response_size,
    sep_bool retry
);

static void require(sep_bool condition) {
    if (!condition) {
        sep_fatal_wait_loop();
    }
}

static sep_bool valid_key_slot(
    const sep_ake_context_t *context,
    sep_u8 key_slot
) {
    const sep_ake_mode_capabilities_t *capabilities =
        sep_ake_get_mode_capabilities(context);
    if (key_slot == 0xff) {
        return capabilities->special_slot_selector != 0;
    }
    return key_slot != 0 && key_slot <= capabilities->maximum_key_slot;
}

void sep_ake_execute_transport_command(
    sep_ake_context_t *context,
    const sep_u8 *request,
    sep_size_t request_size,
    sep_u8 *response,
    sep_size_t response_size
) {
    require(context != NULL && request != NULL && response != NULL &&
        request_size >= 4 && response_size >= 4 && request[0] < 0xe3);
    context->transport_status_token = NULL;
    context->transport_failed = 0;
    sep_ake_validate_transport_provider(
        context->transport_id,
        request,
        response
    );
    if (!open_secure_rom_ake_exchange(context->transport_id, request,
        request_size, response, response_size, 0)) {
        sep_ake_handle_transport_failure(context);
    }
    if (response[2] != 0 || response[0] != request[0] ||
        response[1] != request[1]) {
        sep_ake_handle_transport_failure(context);
    }
    if (response[3] != 0x80) {
        context->transport_status_token = (const void *)(sep_size_t)response[3];
        context->transport_failed = 1;
        return;
    }

    const sep_ake_message_prefix_t *prefix =
        (const sep_ake_message_prefix_t *)(const void *)response;
    sep_bool authenticated = 1;
    switch (request[0]) {
    case 1:
        require(request_size == 116 && response_size == 116 &&
            context->connect_cmac_key != NULL);
        authenticated = sep_ake_verify_connect_response_cmac(
            response + 4,
            context->connect_cmac_key,
            prefix,
            request + 20,
            response + 20
        );
        break;
    case 3:
    case 5:
        require(context->active_session != NULL && response_size == 20);
        authenticated = sep_ake_ccm_decrypt_and_verify_response(
            context->active_session,
            prefix,
            NULL,
            0,
            response + 4,
            NULL
        );
        break;
    case 4:
        require(context->active_session != NULL &&
            context->record_output != NULL && response_size >= 20 &&
            ((response_size - 20) & 15) == 0);
        authenticated = sep_ake_ccm_decrypt_and_verify_response(
            context->active_session,
            prefix,
            response + 20,
            response_size - 20,
            response + 4,
            context->record_output
        );
        break;
    case 6:
        require(context->active_session != NULL &&
            context->metadata_output != NULL && response_size == 52);
        authenticated = sep_ake_ccm_decrypt_and_verify_response(
            context->active_session,
            prefix,
            response + 20,
            32,
            response + 4,
            context->metadata_output
        );
        break;
    default:
        break;
    }
    if (!authenticated) {
        sep_ake_handle_transport_failure(context);
    }
}

sep_bool sep_ake_connect_key_slot(
    sep_ake_context_t *context,
    sep_u8 key_slot,
    const sep_u8 *key_material,
    sep_size_t key_material_length
) {
    require(context != NULL && valid_key_slot(context, key_slot) &&
        key_material != NULL && key_material_length == 32);
    context->active_command = 1;
    if (sep_ake_find_session_slot(context, key_slot) != NULL) {
        context->active_command = 0xe3;
        return 1;
    }
    const sep_u8 capacity = sep_ake_get_mode_capabilities(context)
        ->session_capacity;
    sep_ake_session_slot_t *slot = NULL;
    for (sep_u8 index = 0; index < capacity; ++index) {
        if (context->sessions[index].valid != 1) {
            slot = &context->sessions[index];
            break;
        }
    }
    require(slot != NULL);

    sep_u8 request[116];
    sep_u8 response[116];
    sep_u8 mac_key[32];
    sep_u8 session_material[72];
    sep_memzero(request, sizeof(request));
    sep_memzero(response, sizeof(response));
    sep_ake_message_prefix_t *prefix =
        (sep_ake_message_prefix_t *)(void *)request;
    prefix->command = 1;
    prefix->key_slot = key_slot;
    static const sep_u8 mac_label[16] = {
        'A', 'K', 'E', '_', 'M', 'A', 'C', 'K', 'e', 'y', '\n', '\n',
        '\n', '\n', '\n', '\n'
    };
    static const sep_u8 public_label[16] = {
        'A', 'K', 'E', '_', 'P', 'u', 'b', 'l', 'i', 'c', 'S', 'e', 'e',
        'd', '\n', '\n'
    };
    static const sep_u8 session_label[16] = {
        'A', 'K', 'E', '_', 'S', 'e', 's', 's', 'i', 'o', 'n', 'S', 'e',
        'e', 'd', '\n'
    };
    require(sep_ake_kbkdf_cmac_derive(key_material, mac_label, request,
        mac_key, sizeof(mac_key)));
    require(sep_ake_kbkdf_cmac_derive(key_material, public_label, request,
        request + 20, 96));
    sep_ake_compute_connect_request_cmac(
        request + 4,
        mac_key,
        prefix,
        request + 20
    );
    context->connect_cmac_key = mac_key;
    sep_ake_execute_transport_command(
        context,
        request,
        sizeof(request),
        response,
        sizeof(response)
    );
    context->connect_cmac_key = NULL;
    if (context->transport_failed) {
        context->active_command = 0xe3;
        sep_memzero(request, sizeof(request));
        sep_memzero(response, sizeof(response));
        sep_memzero(mac_key, sizeof(mac_key));
        return 0;
    }
    require(sep_ake_kbkdf_cmac_derive(key_material, session_label, request,
        session_material, sizeof(session_material)));
    slot->valid = 1;
    slot->key_slot = key_slot;
    slot->counter = 0;
    sep_memmove(slot->nonce_seed, session_material, sizeof(slot->nonce_seed));
    sep_memmove(
        slot->request_key,
        session_material + 8,
        sizeof(slot->request_key)
    );
    sep_memmove(
        slot->response_key,
        session_material + 40,
        sizeof(slot->response_key)
    );
    context->active_command = 0xe3;
    sep_memzero(request, sizeof(request));
    sep_memzero(response, sizeof(response));
    sep_memzero(mac_key, sizeof(mac_key));
    sep_memzero(session_material, sizeof(session_material));
    return 1;
}

void sep_ake_disconnect_key_slot(sep_ake_context_t *context, sep_u8 key_slot) {
    require(context != NULL && valid_key_slot(context, key_slot));
    context->active_command = 2;
    sep_ake_session_slot_t *slot = sep_ake_find_session_slot(
        context,
        key_slot
    );
    require(slot != NULL);
    sep_u8 request[4] = {2, key_slot, 0, 0};
    sep_u8 response[4] = {0};
    sep_ake_execute_transport_command(
        context,
        request,
        sizeof(request),
        response,
        sizeof(response)
    );
    if (!context->transport_failed) {
        sep_memzero(slot, sizeof(*slot));
    }
    context->active_command = 0xe3;
}

void sep_ake_read_authenticated_record(
    sep_ake_context_t *context,
    sep_u8 key_slot,
    sep_u8 request_flags,
    sep_u8 *output
) {
    require(context != NULL && context->transport_mode != 5 &&
        valid_key_slot(context, key_slot) && request_flags < 4 &&
        output != NULL);
    context->active_command = 4;
    sep_ake_session_slot_t *slot =
        sep_ake_require_session_slot_for_authenticated_request(
            context,
            key_slot
        );
    sep_u8 request[20];
    sep_u8 response[84];
    sep_memzero(request, sizeof(request));
    sep_memzero(response, sizeof(response));
    sep_ake_message_prefix_t *prefix =
        (sep_ake_message_prefix_t *)(void *)request;
    prefix->command = 4;
    prefix->key_slot = key_slot;
    prefix->flags = request_flags;
    sep_ake_ccm_authenticate_empty_request_and_advance_counter(
        slot,
        prefix,
        request + 4
    );
    context->active_session = slot;
    context->record_output = output;
    sep_ake_execute_transport_command(
        context,
        request,
        sizeof(request),
        response,
        sizeof(response)
    );
    context->active_session = NULL;
    context->record_output = NULL;
    context->active_command = 0xe3;
    sep_memzero(request, sizeof(request));
    sep_memzero(response, sizeof(response));
}

void sep_ake_read_record_metadata(
    sep_ake_context_t *context,
    sep_u8 key_slot,
    sep_u8 data_slot,
    sep_u8 request_flags,
    sep_u8 *output,
    sep_size_t output_size
) {
    require(context != NULL && context->transport_mode != 5 &&
        valid_key_slot(context, key_slot) && data_slot != 0 &&
        data_slot <= sep_ake_get_mode_capabilities(context)->maximum_key_slot &&
        request_flags < 4 && output != NULL && output_size == 32);
    context->active_command = 6;
    sep_ake_session_slot_t *slot =
        sep_ake_require_session_slot_for_authenticated_request(
            context,
            key_slot
        );
    sep_u8 request[20];
    sep_u8 response[52];
    sep_memzero(request, sizeof(request));
    sep_memzero(response, sizeof(response));
    sep_ake_message_prefix_t *prefix =
        (sep_ake_message_prefix_t *)(void *)request;
    prefix->command = 6;
    prefix->key_slot = key_slot;
    prefix->data_slot = data_slot;
    prefix->flags = request_flags;
    sep_ake_ccm_authenticate_empty_request_and_advance_counter(
        slot,
        prefix,
        request + 4
    );
    context->active_session = slot;
    context->metadata_output = output;
    sep_ake_execute_transport_command(
        context,
        request,
        sizeof(request),
        response,
        sizeof(response)
    );
    context->active_session = NULL;
    context->metadata_output = NULL;
    context->active_command = 0xe3;
    sep_memzero(request, sizeof(request));
    sep_memzero(response, sizeof(response));
}

void sep_ake_finalize_transport(sep_ake_context_t *context) {
    require(context != NULL);
    sep_u8 request[4] = {8, 0, 0, 0};
    sep_u8 response[4] = {0};
    sep_ake_execute_transport_command(
        context,
        request,
        sizeof(request),
        response,
        sizeof(response)
    );
    sep_delay_microseconds(9);
}

void __attribute__((noreturn)) sep_ake_handle_transport_failure(
    sep_ake_context_t *context
) {
    require(context != NULL && context->transport_mode < 6);
    sep_ake_transport_failure_record_t record;
    sep_memzero(&record, sizeof(record));
    record.bytes[0] = (sep_u8)context->transport_mode;
    record.bytes[4] = sep_ake_get_transport_status(context);
    sep_ake_cache_transport_failure_record_if_reserved_zero(
        context->transport_status_token,
        &record
    );
    sep_fatal_wait_loop();
}
