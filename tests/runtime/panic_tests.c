#include "open_secure_rom/panic.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected panic fatal path");
    __builtin_unreachable();
}

sep_u64 sep_platform_get_panic_context_word(void) {
    return 0;
}

void sep_protocol_event_log_snapshot(
    sep_u32 output[16],
    sep_size_t output_length
) {
    (void)output;
    (void)output_length;
}

void sep_protocol_diagnostic_record_snapshot(
    sep_u32 output[8],
    sep_size_t output_length
) {
    (void)output;
    (void)output_length;
}

int main(void) {
    assert(sep_panic_record_magic() == 0xddeeaaddbbeeeeffULL);
    assert(sep_panic_get_auxiliary_state_byte() == 0);
    assert(sep_assertion_get_last_site_tag() == 0);

    sep_u64 frames[4] = {0};
    sep_panic_unwind_frame_chain(frames, 4, 0);
    for (sep_size_t index = 0; index < 4; ++index) {
        assert(frames[index] == 0);
    }
}
