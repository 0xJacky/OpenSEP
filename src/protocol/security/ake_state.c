#include "open_secure_rom/ake.h"

#include "open_secure_rom/runtime.h"

_Static_assert(sizeof(sep_ake_message_prefix_t) == 4, "AKE prefix ABI");
_Static_assert(sizeof(sep_ake_session_slot_t) == 80, "AKE session ABI");
_Static_assert(
    offsetof(sep_ake_context_t, sessions) == 100,
    "AKE session table offset"
);
_Static_assert(
    offsetof(sep_ake_context_t, transport_mode) == 500,
    "AKE transport mode offset"
);
_Static_assert(
    offsetof(sep_ake_context_t, transport_status_token) == 512,
    "AKE status token offset"
);
_Static_assert(
    offsetof(sep_ake_context_t, transport_failed) == 520,
    "AKE transport failure offset"
);
_Static_assert(
    offsetof(sep_ake_context_t, transport_id) == 577,
    "AKE transport selector offset"
);

static const sep_ake_mode_capabilities_t mode_capabilities[6] = {
    {5, 0x45, 0x16},
    {4, 0x48, 0x00},
    {4, 0x45, 0x00},
    {5, 0x46, 0x0c},
    {5, 0x49, 0x00},
    {5, 0x0f, 0x16},
};

static const sep_u32 mode1_timeouts[0xe3] = {
    0x0ad570, 0x055730, 0x000898, 0x011170, 0x001b58,
    0x0027d8, 0x001b58, 0x000d48, 0x000898, 0x002328,
};

static const sep_u32 modes034_timeouts[0xe3] = {
    0x0c0df0, 0x05dfe8, 0x0007d0, 0x011170, 0x001b58,
    0x002710, 0x001770, 0x000bb8, 0x000bb8, 0x001f40,
    0x004650, 0x00c350, 0x00cb20, 0x003e80, 0x002328,
};

static const sep_u32 extended_timeouts[0xe3] = {
    0x07c830, 0x03d090,
};

static const sep_u32 mode5_timeouts[0xe3] = {
    0x04a768, 0x027100, 0x0007d0, 0x00f230, 0x0039d0,
    0x00add4, 0x002454, 0x0007d0, 0x000708, 0x002bc0,
    0, 0x00e290, 0x00d6d8, 0x009664, 0x00251c, 0,
    0x00060e, 0x000514, 0x006f54, 0x00060e,
    [32] = 0x002008,
    [33] = 0x007a44,
    [34] = 0x0077ec,
    [35] = 0x00701c,
    [36] = 0x0078b4,
    [37] = 0x000c1c,
    [38] = 0x000578,
    [39] = 0x000546,
    [224] = 0x000514,
    [225] = 0x006ef0,
    [226] = 0x000578,
};

static const sep_u32 mode5_extended_timeouts[0xe3] = {
    0x039210, 0x01f018,
};

static sep_ake_transport_exchange_fn transport_exchange;
static void *transport_exchange_opaque;

static void require(sep_bool condition) {
    if (!condition) {
        sep_fatal_wait_loop();
    }
}

void open_secure_rom_ake_context_initialize(
    sep_ake_context_t *context,
    sep_u32 mode,
    sep_u8 transport_id
) {
    require(context != NULL && mode < 6);
    sep_memzero(context, sizeof(*context));
    context->transport_mode = mode;
    context->active_command = 0xe3;
    context->transport_id = transport_id;
}

void open_secure_rom_ake_set_transport_exchange(
    sep_ake_transport_exchange_fn exchange,
    void *opaque
) {
    transport_exchange = exchange;
    transport_exchange_opaque = opaque;
}

sep_bool open_secure_rom_ake_exchange(
    sep_u8 transport_id,
    const sep_u8 *request,
    sep_size_t request_size,
    sep_u8 *response,
    sep_size_t response_size,
    sep_bool retry
) {
    if (transport_exchange == NULL) {
        return 0;
    }
    return transport_exchange(
        transport_id,
        request,
        request_size,
        response,
        response_size,
        retry,
        transport_exchange_opaque
    );
}

sep_bool sep_ake_transport_exchange_status_stub(
    sep_u8 transport_id,
    const void *request,
    void *response,
    sep_bool retry
) {
    (void)transport_id;
    (void)request;
    (void)response;
    (void)retry;
    return 1;
}

sep_bool sep_ake_validate_transport_provider(
    sep_u8 transport_id,
    const void *request,
    const void *response
) {
    (void)transport_id;
    require(request != NULL && response != NULL && transport_exchange != NULL);
    return 1;
}

sep_bool sep_ake_buffer_has_nonzero_byte(
    const void *buffer,
    sep_size_t length
) {
    const sep_u8 *bytes = buffer;
    sep_u8 combined = 0;
    for (sep_size_t index = 0; index < length; ++index) {
        combined |= bytes[index];
    }
    return combined != 0;
}

int sep_ake_zero_rng_generate(
    sep_ccrng_state_t *rng,
    sep_size_t output_length,
    void *output
) {
    (void)rng;
    sep_memzero(output, output_length);
    return 0;
}

sep_ccrng_state_t *sep_ake_get_zero_rng_state(void) {
    static sep_ccrng_state_t state = {sep_ake_zero_rng_generate};
    return &state;
}

const sep_ake_mode_capabilities_t *sep_ake_get_mode_capabilities(
    const sep_ake_context_t *context
) {
    require(context != NULL && context->transport_mode < 6);
    require(context->transport_mode != 4 || context->transport_id != 0);
    return &mode_capabilities[context->transport_mode];
}

sep_ake_session_slot_t *sep_ake_find_session_slot(
    sep_ake_context_t *context,
    sep_u8 key_slot
) {
    const sep_u8 capacity = sep_ake_get_mode_capabilities(context)
        ->session_capacity;
    for (sep_u8 index = 0; index < capacity; ++index) {
        sep_ake_session_slot_t *slot = &context->sessions[index];
        if (slot->valid == 1 && slot->key_slot == key_slot) {
            return slot;
        }
    }
    return NULL;
}

sep_ake_session_slot_t *sep_ake_require_session_slot_for_authenticated_request(
    sep_ake_context_t *context,
    sep_u8 key_slot
) {
    sep_ake_session_slot_t *slot = sep_ake_find_session_slot(context, key_slot);
    require(slot != NULL && slot->counter < 0xffffe);
    return slot;
}

sep_u8 sep_ake_get_transport_status(const sep_ake_context_t *context) {
    if (context->transport_failed != 1) {
        return 0x80;
    }
    return (sep_u8)(sep_size_t)context->transport_status_token;
}

void sep_ake_build_ccm_nonce(
    const sep_ake_session_slot_t *slot,
    sep_u8 *nonce
) {
    for (sep_size_t index = 0; index < 8; ++index) {
        nonce[index] = slot->nonce_seed[index];
    }
    nonce[8] = (sep_u8)(slot->counter >> 24);
    nonce[9] = (sep_u8)(slot->counter >> 16);
    nonce[10] = (sep_u8)(slot->counter >> 8);
    nonce[11] = (sep_u8)slot->counter;
}

void sep_ake_build_ccm_aad(
    const sep_ake_session_slot_t *slot,
    const sep_ake_message_prefix_t *prefix,
    sep_u8 *aad
) {
    aad[0] = prefix->command;
    aad[1] = prefix->key_slot;
    aad[2] = prefix->data_slot;
    aad[3] = prefix->flags;
    aad[4] = (sep_u8)(slot->counter >> 24);
    aad[5] = (sep_u8)(slot->counter >> 16);
    aad[6] = (sep_u8)(slot->counter >> 8);
    aad[7] = (sep_u8)slot->counter;
}

sep_u32 sep_ake_timeout_for_transport_mode1(
    sep_ake_transport_command_t command,
    sep_bool use_extended_limit
) {
    require(command < 0xe3);
    if (use_extended_limit && extended_timeouts[command] != 0) {
        return extended_timeouts[command];
    }
    return mode1_timeouts[command];
}

sep_u32 sep_ake_timeout_for_transport_modes_0_3_4(
    const sep_ake_message_prefix_t *request,
    sep_bool use_extended_limit
) {
    require(request != NULL && request->command < 0xe3);
    if (request->command == 3) {
        if (request->data_slot == 0) {
            return 1000000;
        }
        return request->data_slot == 0xff ? 420000 : 70000;
    }
    if (use_extended_limit && extended_timeouts[request->command] != 0) {
        return extended_timeouts[request->command];
    }
    return modes034_timeouts[request->command];
}

sep_u32 sep_ake_timeout_for_transport_mode5(
    const sep_ake_message_prefix_t *request,
    sep_bool use_extended_limit
) {
    require(request != NULL && request->command < 0xe3);
    if (request->command == 3) {
        if (request->data_slot == 0) {
            return 557000;
        }
        return request->data_slot == 0xff ? 342000 : 62000;
    }
    if (use_extended_limit &&
        mode5_extended_timeouts[request->command] != 0) {
        return mode5_extended_timeouts[request->command];
    }
    return mode5_timeouts[request->command];
}

sep_u32 sep_ake_resolve_command_timeout_us(
    const sep_ake_context_t *context,
    const sep_ake_message_prefix_t *request,
    sep_bool use_extended_limit
) {
    require(context != NULL && request != NULL && request->command < 0xe3);
    switch (context->transport_mode) {
    case 0:
    case 3:
    case 4:
        return sep_ake_timeout_for_transport_modes_0_3_4(
            request,
            use_extended_limit
        );
    case 1:
        return sep_ake_timeout_for_transport_mode1(
            request->command,
            use_extended_limit
        );
    case 2: {
        const sep_u32 one = sep_ake_timeout_for_transport_mode1(
            request->command,
            use_extended_limit
        );
        const sep_u32 common = sep_ake_timeout_for_transport_modes_0_3_4(
            request,
            use_extended_limit
        );
        const sep_u32 five = sep_ake_timeout_for_transport_mode5(
            request,
            use_extended_limit
        );
        const sep_u32 first = one > common ? one : common;
        return first > five ? first : five;
    }
    case 5:
        return sep_ake_timeout_for_transport_mode5(
            request,
            use_extended_limit
        );
    default:
        sep_fatal_wait_loop();
    }
}
