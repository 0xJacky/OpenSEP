/*
 * The real SEPOS image, decoded on the host.
 *
 * A boot on the emulated machine takes minutes and each of these decisions
 * is one branch, so they are worth taking apart here first.  The file is the
 * same bytes the kernel hands the ROM: `RestoreSEP` personalised out of the
 * IPSW, which is byte for byte what dart-sep's IOVA 0x4000 resolves to in a
 * running boot.
 *
 * The path comes from the first argument or OPENSEP_SEPFW_IMAGE (a
 * personalised 21A329 RestoreSEP.img4).  Without either this says so and
 * passes, so `make verify` stays green on a tree that does not have it.
 */
#include "open_secure_rom/aes.h"
#include "open_secure_rom/img4.h"
#include "open_secure_rom/shared_image.h"
#include "open_secure_rom/system_closure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The terminals, as reports rather than as ends.  On the part these stop the
 * core; here the whole point is to be told which one was reached.
 */
void __attribute__((noreturn)) sep_fatal_wait_loop(void) {
    printf("  STOP: fatal wait loop\n");
    exit(0);
}

void __attribute__((noreturn)) sep_abort_to_fatal_wait_loop(void) {
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_wait_for_event_forever(void) {
    sep_fatal_wait_loop();
}

void __attribute__((noreturn)) sep_assertion_fail_with_site(const void *site) {
    printf("  STOP: assertion at %p\n", site);
    exit(0);
}

/* The panic reasons are already given host bodies by panic.c. */

#define IMAGE_PATH_ENV "OPENSEP_SEPFW_IMAGE"

/* The `argument` byte of the mailbox frame that hands the image over. */
#define BOOT_MODE 1

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *path = argc > 1 ? argv[1] : getenv(IMAGE_PATH_ENV);
    if (path == NULL || path[0] == '\0') {
        printf("sepfw: %s not set; skipping\n", IMAGE_PATH_ENV);
        return 0;
    }
    FILE *handle = fopen(path, "rb");

    if (handle == NULL) {
        printf("sepfw: no image at %s; nothing to decode\n", path);
        return 0;
    }
    fseek(handle, 0, SEEK_END);
    long length = ftell(handle);
    fseek(handle, 0, SEEK_SET);
    unsigned char *data = malloc((size_t)length);
    if (data == NULL || fread(data, 1, (size_t)length, handle) != (size_t)length) {
        printf("sepfw: could not read %s\n", path);
        return 1;
    }
    fclose(handle);
    printf("sepfw: %ld bytes, %02x %02x %02x %02x\n",
           length, data[0], data[1], data[2], data[3]);

    sep_shared_image_context_t image =
        sep_shared_image_decode_and_evaluate(BOOT_MODE, data, (sep_size_t)length);

    static const char *const names[] = {
        [256] = "decoded",
        [257] = "platform constraints",
        [258] = "payload properties",
        [259] = "payload digest",
        [260] = "payload digest again",
        [261] = "overall verdict",
        [262] = "manifest evaluated",
    };
    for (int index = 256; index <= 262; index++) {
        printf("  properties[%d] %-22s = %u\n", index, names[index],
               image.decoded_properties[index]);
    }

    const sep_bool canaries_valid = sep_img4_root_key_canaries_are_valid(1);
    printf("  root key canaries valid    = %u\n", canaries_valid);
    const sep_bool canaries =
        (sep_bool)(canaries_valid & image.decoded_properties[261]);
    printf("  canaries AND verdict       = %u\n", canaries);

    if (!canaries) {
        /*
         * What `sep_shared_region_import_and_commit` does on this branch
         * before it looks at the keybag: the payload is to be taken as it
         * stands.
         */
        sep_shared_image_properties_set_ekey(
            (sep_shared_image_properties_t *)(void *)&image, 0);
        printf("  ekey cleared\n");
    }
    printf("  ekey now                   = %u\n",
           sep_shared_image_properties_ekey_checked(
               (const sep_shared_image_properties_t *)(const void *)&image));

    const sep_bool keybag_wanted =
        sep_shared_image_payload_keybag_is_present_and_allowed(
            &image, (sep_bool)(canaries ^ 1));
    printf("  keybag present and allowed = %u\n", keybag_wanted);
    if (keybag_wanted) {
        const sep_shared_image_payload_keybag_t keybag =
            sep_shared_image_select_payload_keybag_for_payload(
                (const sep_shared_image_auxiliary_t *)(const void *)
                    image.auxiliary,
                image.payload_data,
                image.payload_size);
        printf("  selected keybag present    = %u (bits %u)\n",
               keybag.present, keybag.key_bit_length);
        if (keybag.present) {
            /*
             * And the decrypt itself, through the ROM's own AES, in place, the
             * way `sep_shared_region_import_and_commit` does it.
             */
            unsigned char *payload = malloc(image.payload_size);
            if (payload != NULL) {
                memcpy(payload, image.payload_data, image.payload_size);
                const sep_bool ok = sep_aes_cbc_decrypt_checked(
                    payload, payload, image.payload_size,
                    keybag.key, keybag.key_bit_length, keybag.metadata);
                printf("  decrypt of %zu bytes       = %u\n",
                       (size_t)image.payload_size, ok);
                if (ok) {
                    printf("  first instructions         =");
                    for (int n = 0; n < 4; n++) {
                        unsigned word;
                        memcpy(&word, payload + n * 4, 4);
                        printf(" %08x", word);
                    }
                    printf("\n");
                }
                free(payload);
            }
        }
    }
    free(data);
    return 0;
}
