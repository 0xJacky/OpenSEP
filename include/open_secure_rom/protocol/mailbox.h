#ifndef OPEN_SECURE_ROM_MAILBOX_H
#define OPEN_SECURE_ROM_MAILBOX_H

#include "open_secure_rom/types.h"

enum {
    SEP_MAILBOX_REQUEST_QUERY_CAPABILITY = 0x01,
    SEP_MAILBOX_REQUEST_QUERY_PHASE = 0x02,
    SEP_MAILBOX_REQUEST_INITIALIZE_RESEARCH_SEED = 0x03,
    SEP_MAILBOX_REQUEST_READ_RESEARCH_SEED_WORD = 0x04,
    SEP_MAILBOX_REQUEST_PUBLISH_AKE_READY = 0x05,
    SEP_MAILBOX_REQUEST_PUBLISH_SHARED_REGION = 0x06,
    SEP_MAILBOX_REQUEST_STREAM_RESEARCH_PATTERN = 0x10,
    SEP_MAILBOX_REQUEST_SET_COMMAND11_WORD = 0x11,
    SEP_MAILBOX_REQUEST_INITIALIZE_RESEARCH_VALUE64 = 0x21,
    SEP_MAILBOX_REQUEST_READ_RESEARCH_VALUE64_WORD = 0x22,
};

void sep_mailbox_activate_and_wait_ready(void);
void sep_mailbox_send_startup_event(sep_u32 phase);
void sep_mailbox_build_and_send_response(sep_u8 tag, sep_u8 argument, sep_u32 payload);
sep_mailbox_slot_t sep_mailbox_receive_slot(void);
void sep_mailbox_send_slot(const sep_mailbox_slot_t *slot);
sep_u8 sep_mailbox_take_pending_sequence(void);
void sep_mailbox_send_c7_payload_response(sep_u32 payload);
void sep_mailbox_send_empty_response(sep_u8 tag);
void sep_mailbox_send_tag_6a_empty_response(void);
sep_u64 sep_mailbox_get_shared_region_base(void);
sep_u8 sep_mailbox_get_shared_region_mode(void);
sep_u32 sep_mailbox_get_command11_word(void);
void sep_platform_mailbox_command9(sep_bool has_upper_word);
void sep_platform_protocol_shutdown(sep_bool shutting_down);
void sep_platform_mailbox_command19(void);
void sep_protocol_transition_noop_hook(void);
void open_secure_rom_mailbox_protocol_reset(void);
sep_u32 sep_mailbox_receive_and_dispatch_requests(void);
void __attribute__((noreturn)) sep_mailbox_protocol_coordinator(void);

#endif
