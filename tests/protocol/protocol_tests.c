#include "open_secure_rom/mailbox.h"
#include "open_secure_rom/protocol.h"

#include <assert.h>

void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    assert(0 && "unexpected SecureROM fatal path");
    __builtin_unreachable();
}

int main(void) {
    open_secure_rom_protocol_phase_reset();
    assert(open_secure_rom_protocol_phase() == 0);

    sep_protocol_dispatch_result_t result =
        sep_protocol_dispatch_request(0x00000000000643ffULL);
    assert(result.has_response == 1);
    assert(result.phase == 0);
    assert(result.response.low == 0x0000000600c743ffULL);

    result = sep_protocol_dispatch_request(0x00000000000244ffULL);
    assert(result.response.low == 0x00000001006644ffULL);

    result = sep_protocol_dispatch_request(0x00000000000545ffULL);
    assert(result.has_response == 1);
    assert(result.phase == 1);
    assert(result.response.low == 0x00000000006945ffULL);
    assert(open_secure_rom_protocol_phase() == 1);

    result = sep_protocol_dispatch_request(0x00000000000246ffULL);
    assert(result.response.low == 0x00000002006646ffULL);

    result = sep_protocol_dispatch_request(0x00000000000547ffULL);
    assert(result.has_response == 1);
    assert(result.phase == 0);
    assert(result.response.low == 0x0000000500c747ffULL);

    result = sep_protocol_dispatch_request(0x00008000000648ffULL);
    assert(result.has_response == 0);
    assert(result.phase == 2);
    assert(result.shared_region_base == 0x08000000ULL);
    assert(result.shared_region_mode == 0);
    assert(open_secure_rom_protocol_phase() == 2);

    open_secure_rom_protocol_phase_reset();
    result = sep_protocol_dispatch_request(0x00000000000549ffULL);
    assert(result.phase == 1);
    result = sep_protocol_dispatch_request(0x0001234501064affULL);
    assert(result.has_response == 0);
    assert(result.phase == 2);
    assert(result.shared_region_base == 0x12345000ULL);
    assert(result.shared_region_mode == 1);

    open_secure_rom_protocol_phase_reset();
    sep_clear_research_seed();
    sep_optional_research_seed_t seed = sep_get_optional_research_seed();
    assert(seed.present == 0);
    assert(sep_initialize_research_seed() == 1);
    seed = sep_get_optional_research_seed();
    assert(seed.present == 1);
    const sep_u8 seed_pattern[4] = {0xef, 0xbe, 0xad, 0xde};
    for (sep_u8 index = 0; index < sizeof(seed.bytes); ++index) {
        assert(seed.bytes[index] == seed_pattern[index & 3]);
    }

    result = sep_protocol_dispatch_request(0x00000000000367ffULL);
    assert(result.has_response == 1);
    assert(result.response.low == 0x000000a0006767ffULL);
    assert(result.response.high == 0);

    for (sep_u8 index = 0; index < 5; ++index) {
        const sep_u64 request = 0xffULL | 0x6e00ULL | 0x00040000ULL |
            ((sep_u64)index << 24);
        result = sep_protocol_dispatch_request(request);
        assert(result.response.low ==
            (0xdeadbeef00686effULL | ((sep_u64)index << 24)));
    }

    for (sep_u8 index = 0; index < 8; ++index) {
        result = sep_protocol_dispatch_request(0x00000000000170ffULL);
        assert(result.response.low == 0x00000000006570ffULL);
    }

    for (sep_u8 index = 0; index < 8; ++index) {
        result = sep_protocol_dispatch_request(0x00000000001044ffULL);
        assert(result.response.low == 0xdeadbeef007444ffULL);
    }

    result = sep_protocol_dispatch_request(0x12345678001155ffULL);
    assert(result.response.low == 0x00000000007555ffULL);
    assert(sep_mailbox_get_command11_word() == 0x12345678);

    result = sep_protocol_dispatch_request(0x00000000002188ffULL);
    assert(result.response.low == 0x00000040008588ffULL);
    result = sep_protocol_dispatch_request(0x00000000002288ffULL);
    assert(result.response.low == 0xdeadbeef008688ffULL);
    result = sep_protocol_dispatch_request(0x00000000012288ffULL);
    assert(result.response.low == 0xdeadbeef018688ffULL);

    result = sep_protocol_dispatch_request(0x00000000000712ffULL);
    assert(result.response.low == 0x0000000700c712ffULL);
}
