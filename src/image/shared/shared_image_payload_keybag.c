#include "open_secure_rom/shared_image.h"

#include "open_secure_rom/aes.h"
#include "open_secure_rom/event_log.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"

sep_shared_image_payload_keybag_t sep_shared_image_select_payload_keybag(
    const sep_shared_image_auxiliary_t *auxiliary
) {
    if (auxiliary == NULL) sep_panic_reason_1a();
    if (auxiliary->present >= 2) sep_panic_reason_27();
    if (!auxiliary->present) sep_panic_with_reason_and_pc(1266, 0);

    const sep_shared_image_auxiliary_keybag_entry_t *entry =
        &auxiliary->entries[0];
    if (entry->present >= 2) sep_panic_reason_27();
    if (entry->present) return *entry;

    sep_shared_image_payload_keybag_t selected;
    sep_shared_image_payload_keybag_initialize_absent(&selected);
    /*
     * No keybag in the image.  On this part that is not the end of it: the
     * firmware key is one the part knows outright, because there is no GID
     * here to unwrap one with.  See `sep_platform_firmware_key`.
     */
    if (sep_platform_firmware_key(&selected)) {
        return selected;
    }
    if (!sep_platform_payload_keybag_policy_zero_stub(0)) return selected;

    const sep_u16 encoded = (sep_u16)sep_platform_read_flag_0c_encoded();
    if ((encoded & 0xfeU) != 0 || (encoded & 0xff00U) > 0x100U) {
        sep_panic_reason_27();
    }
    const sep_u32 index = (encoded & 0x101U) == 0x101U ? 1 : 2;
    entry = &auxiliary->entries[index];
    if (entry->present >= 2) sep_panic_reason_27();
    if (!entry->present) return selected;
    if ((entry->key_bit_length & 7U) != 0) {
        sep_panic_with_reason_and_pc(1298, 0);
    }
    if (entry->key_bit_length >= 0x108U) {
        sep_panic_with_reason_and_pc(1300, 0);
    }

    sep_u8 transformed[48] = {0};
    sep_u8 iv[16] = {0};
    sep_memmove(transformed, entry->metadata, 16);
    sep_memmove(transformed + 16, entry->key, entry->key_bit_length >> 3);
    if (sep_platform_payload_keybag_selector_zero_stub(
            transformed,
            transformed,
            16 + (entry->key_bit_length >> 3),
            iv,
            entry->key_bit_length)) {
        selected.present = 1;
        selected.key_bit_length = entry->key_bit_length;
        sep_memmove(selected.metadata, transformed, 16);
        sep_memmove(
            selected.key,
            transformed + 16,
            entry->key_bit_length >> 3
        );
    }
    return selected;
}

/*
 * SEPOS's reset sequence, the same in every build of it: adr x1, #0 then
 * adr x2, #0x7fc then msr vbar_el1, x2.  The fourth word is a branch whose
 * displacement differs between builds, so only these three are compared.
 *
 * This is what makes a trial decryption decidable.  Nothing in the image says
 * which firmware key it was sealed with -- the tag is 'sepi' or 'rsep' either
 * way -- so the payload itself has to be asked.
 */
static const sep_u8 shared_image_runtime_reset_prologue[12] = {
    0x01, 0x00, 0x00, 0x10,
    0xe2, 0x3f, 0x00, 0x10,
    0x02, 0xc0, 0x18, 0xd5,
};

sep_shared_image_payload_keybag_t
sep_shared_image_select_payload_keybag_for_payload(
    const sep_shared_image_auxiliary_t *auxiliary,
    const void *ciphertext,
    sep_size_t ciphertext_length
) {
    /*
     * A keybag in the image is of no use to us: entry zero is still wrapped
     * with the GID, and this part has none.  So before honouring it, ask each
     * key the part knows whether it is the one that opens this payload, and
     * decide on the answer rather than on anything the image claims.
     */
    if (ciphertext != NULL && ciphertext_length >= 16) {
        const sep_u32 count = sep_platform_firmware_key_count();
        for (sep_u32 index = 0; index < count; ++index) {
            sep_shared_image_payload_keybag_t candidate;
            sep_shared_image_payload_keybag_initialize_absent(&candidate);
            if (!sep_platform_firmware_key_at(index, &candidate)) continue;

            sep_u8 probe[16];
            if (!sep_aes_cbc_decrypt_checked(
                    probe,
                    ciphertext,
                    sizeof(probe),
                    candidate.key,
                    candidate.key_bit_length,
                    candidate.metadata
                )) {
                continue;
            }
            sep_size_t at = 0;
            while (at < sizeof(shared_image_runtime_reset_prologue) &&
                   probe[at] == shared_image_runtime_reset_prologue[at]) {
                ++at;
            }
            if (at == sizeof(shared_image_runtime_reset_prologue)) {
                sep_protocol_event_log_append(0x20006U | (index << 16));
                return candidate;
            }
        }
    }

    return sep_shared_image_select_payload_keybag(auxiliary);
}
