#include "open_secure_rom/system_closure.h"

#include "open_secure_rom/aes.h"
#include "open_secure_rom/boot_handoff.h"
#include "open_secure_rom/configuration_sink.h"
#include "open_secure_rom/event_log.h"
#include "open_secure_rom/img4.h"
#include "open_secure_rom/mailbox.h"
#include "open_secure_rom/panic.h"
#include "open_secure_rom/platform.h"
#include "open_secure_rom/runtime.h"
#include "open_secure_rom/runtime_handoff.h"
#include "open_secure_rom/runtime_storage.h"
#include "open_secure_rom/shared_image.h"

extern void open_secure_rom_runtime_authentication_verify_fallthrough(void);

static void __attribute__((noreturn)) panic_with_caller(sep_u32 reason) {
    sep_panic_with_reason_and_pc(
        reason,
        (sep_u64)(uintptr_t)__builtin_return_address(0)
    );
}

void __attribute__((noreturn)) sep_boot_prepare_and_transfer_runtime(
    const sep_shared_image_context_t *image,
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
) {
    sep_boot_prepare_runtime_mapping(runtime_mode);
    const sep_u64 handoff_address = sep_boot_build_runtime_handoff(
        image,
        payload_length,
        manifest_length,
        runtime_mode
    );
    const sep_boot_runtime_entry_t entry =
        sep_boot_runtime_entry(handoff_address, runtime_mode);
    sep_protocol_event_log_append(0x10009);
    sep_boot_scrub_architectural_state_and_enter_runtime(
        entry.x0,
        entry.x1,
        entry.address,
        entry.power_down_save
    );
}

void __attribute__((noreturn)) sep_shared_region_import_and_commit(
    sep_u64 shared_region_base,
    sep_u8 mode
) {
    sep_platform_transition_stage_noop(6);
    const sep_u32 runtime_mode =
        sep_runtime_region_length_checked(2) != 0 ? 1 : 4;
    sep_u64 region_base = 0;
    sep_size_t region_length = 0;
    sep_runtime_region_get_layout(
        &region_base,
        &region_length,
        runtime_mode
    );
    sep_protocol_event_log_append(0x20003);
    sep_shared_region_load_image(
        shared_region_base,
        (void *)(uintptr_t)region_base,
        region_length
    );
    sep_protocol_event_log_append(0x20006);

    sep_shared_image_context_t image =
        sep_shared_image_decode_and_evaluate(
            mode,
            (const sep_u8 *)(uintptr_t)region_base,
            region_length
        );
    if (image.decoded_properties[261] >= 2) {
        sep_panic_reason_27();
    }
    const sep_bool root_key_canaries = (sep_bool)(
        sep_img4_root_key_canaries_are_valid(1) &
        image.decoded_properties[261]
    );
    if (root_key_canaries) {
        sep_protocol_event_log_append(0x20004);
    } else {
        /*
         * An image whose root-key canaries do not come out valid is used
         * anyway, with its payload treated as unencrypted.
         *
         * This ROM used to refuse -- `panic_with_caller(107)` -- whenever the
         * strict image policy was on, and on this part it is always on: the
         * policy comes from platform flag 0x0c, and the register behind it
         * reads back in a way that forces strict whatever the platform gate
         * says.  There are no real root keys here for the canaries to be
         * valid against, so the refusal could only ever stop the boot; the
         * main processor beside this one already boots manifests of our own
         * making.  See also OPEN_SECURE_ROM_ENFORCE_IMAGE_TRUST in
         * shared_image_decode.c, which is the same decision one step earlier.
         */
        sep_shared_image_properties_set_ekey(
            (sep_shared_image_properties_t *)(void *)&image,
            0
        );
        sep_protocol_event_log_append(0x20005);
    }

    open_secure_rom_shared_region_payload_plan_t plan;
    if (open_secure_rom_shared_region_plan_payload(
            region_base,
            region_length,
            &image,
            &plan
        ) != OPEN_SECURE_ROM_SHARED_REGION_OK) {
        panic_with_caller(140);
    }
    sep_memmove(
        (void *)(uintptr_t)plan.payload_destination,
        image.payload_data,
        plan.payload_length
    );
    if (image.manifest_data != NULL) {
        sep_memmove(
            (void *)(uintptr_t)plan.manifest_destination,
            image.manifest_data,
            plan.manifest_length
        );
    }
    sep_memzero(
        (void *)(uintptr_t)(plan.payload_destination + plan.payload_length),
        plan.payload_capacity - plan.payload_length
    );
    sep_memzero(
        (void *)(uintptr_t)(plan.manifest_destination + plan.manifest_length),
        region_length - plan.payload_capacity - plan.manifest_length
    );

    if (sep_shared_image_payload_keybag_is_present_and_allowed(
            &image,
            (sep_bool)(root_key_canaries ^ 1)
        )) {
        const sep_shared_image_payload_keybag_t keybag =
            sep_shared_image_select_payload_keybag_for_payload(
                (const sep_shared_image_auxiliary_t *)(const void *)
                    image.auxiliary,
                /*
                 * The bytes the decrypt below will actually read, and not
                 * `image.payload_data`: the payload has already been moved
                 * into the shared region by then, over the top of the image
                 * it came from.  Probing the stale source pointer reads a
                 * shifted block, no key matches, and the selection falls back
                 * to the first one in the table -- which is how the runtime
                 * region came to hold the output of the wrong key.
                 */
                (const void *)(uintptr_t)region_base,
                image.payload_size
            );
        if (keybag.present >= 2) {
            sep_panic_reason_27();
        }
        if (!keybag.present) {
            sep_protocol_event_log_append(0x80050021);
            panic_with_caller(187);
        }
        if (!sep_aes_cbc_decrypt_checked(
                (void *)(uintptr_t)region_base,
                (const void *)(uintptr_t)region_base,
                image.payload_size,
                keybag.key,
                keybag.key_bit_length,
                keybag.metadata
            )) {
            sep_protocol_event_log_append(0x80030005);
            panic_with_caller(192);
        }
    }

    sep_runtime_feature_flags_t flags = {
        .valid = 1,
        .flags = {
            (sep_bool)(sep_shared_image_properties_ekey_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ) ^ 1),
            sep_shared_image_properties_dsec_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ),
            sep_shared_image_properties_eg0t_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ),
            sep_shared_image_properties_eg1t_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ),
            sep_shared_image_properties_eg3t_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ),
            sep_shared_image_properties_eg0n_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ),
            sep_shared_image_properties_eg1n_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ),
            sep_shared_image_properties_eg3n_checked(
                (const sep_shared_image_properties_t *)(const void *)&image
            ),
        },
    };
    const sep_u8 packed_flags = sep_runtime_feature_flags_pack(&flags);
    sep_platform_configuration_write_runtime_feature_flags(packed_flags);
    sep_runtime_feature_flags_apply(&flags);
    sep_platform_runtime_feature_commit_noop(0x1f, 1);

    if (image.decoded_properties[262] >= 2) {
        sep_panic_reason_27();
    }
    sep_shared_image_research_policy_t research_policy = 2;
    if (image.decoded_properties[262]) {
        research_policy = sep_shared_image_evaluate_research_policy(&image);
        if (research_policy == 1) {
            sep_protocol_event_log_append(0x20007);
        }
    }
    const sep_bool include_configuration_key = research_policy == 1;
    /*
     * The other half of the same decision: this used to refuse an image
     * whose research policy is not the expected one whenever the strict
     * image policy was on, and on this part it always is.  The payload's
     * key is still checked below.
     */
    if (research_policy != 1 &&
        sep_shared_image_properties_ekey_checked(
            (const sep_shared_image_properties_t *)(const void *)&image
        )) {
        sep_protocol_event_log_append(0x80050006);
        panic_with_caller(272);
    }

    const sep_optional_configuration_key48_t optional_key =
        sep_shared_image_context_get_optional_key48(&image);
    sep_platform_configuration_write_optional_key48(
        &optional_key,
        sep_shared_image_context_payload_type_checked(&image),
        (sep_bool)(image.decoded_properties[261] & 1)
    );
    sep_protocol_event_log_append(0x10008);
    sep_mailbox_send_tag_6a_empty_response();
    sep_platform_transition_noop_hook(0x1f, 1);
    sep_runtime_feature_flags_validate_platform_support(&flags);
    sep_write_context_configuration_key_sink(
        &image,
        include_configuration_key
    );
    sep_platform_publish_runtime_region_size_kib();
    if (sep_platform_zero_result_stub() == 0) {
        sep_platform_runtime_authentication_finalize_noop();
    }
    sep_boot_prepare_and_transfer_runtime(
        &image,
        plan.payload_capacity,
        image.manifest_size,
        runtime_mode
    );
}

void __attribute__((noreturn)) sep_runtime_initialize_regions_and_transfer(
    void
) {
    if (sep_platform_runtime_feature0_enabled()) {
        sep_platform_transition_noop_hook(0, 0);
    }
    if (sep_platform_runtime_feature1_enabled()) {
        sep_platform_transition_noop_hook(1, 0);
    }
    if (sep_platform_zero_result_stub() != 0) {
        sep_protocol_event_log_append(0x80050013);
        panic_with_caller(0x41);
    }
    if (!sep_platform_secondary_runtime_path_enabled()) {
        panic_with_caller(0x47);
    }
    if (sep_platform_runtime_iteration_status(0) != 0) {
        panic_with_caller(0x4c);
    }
    for (sep_u32 slot = 1;
         slot < sep_platform_wrak_autk_slot_count();
         ++slot) {
        if (sep_platform_runtime_iteration_status((sep_u8)slot) == 0) {
            panic_with_caller(0x50);
        }
    }
    if (sep_platform_diagnostic_disclosure_enabled()) {
        sep_platform_transition_noop_hook(0x1e, 1);
    }
    sep_platform_runtime_authentication_state_initialize();
    open_secure_rom_runtime_authentication_verify_fallthrough();

    sep_platform_runtime_region_prepare_noop(0);
    const sep_bool provider_context =
        sep_platform_runtime_configuration_hook_enabled(0);
    if (provider_context) {
        sep_protocol_event_log_append(0x10003);
    }
    const sep_u32 region_size_kib =
        sep_platform_read_runtime_region_size_kib();
    if (region_size_kib == 0) {
        sep_protocol_event_log_append(0x80040012);
        panic_with_caller(0xaf);
    }
    sep_runtime_region_table_initialize(region_size_kib);
    sep_runtime_alternate_handoff_pre_hook();
    sep_runtime_alternate_handoff_post_hook();

    sep_u64 optional_base = 0;
    sep_size_t optional_length = 0;
    sep_runtime_region_get_layout(&optional_base, &optional_length, 5);
    sep_platform_validate_runtime_mode_configuration_blocks(1);
    sep_runtime_mode_configuration_complete_hook(1);
    if (optional_length != 0) {
        sep_platform_validate_runtime_mode_configuration_blocks(4);
        sep_runtime_mode_configuration_complete_hook(4);
    }
    sep_protocol_event_log_append(0x10005);

    sep_runtime_feature_flags_t flags = sep_runtime_feature_flags_decode(
        sep_platform_configuration_read_runtime_feature_flags()
    );
    if (flags.valid != 1) {
        sep_panic_reason_27();
    }
    sep_runtime_feature_flags_apply(&flags);
    sep_platform_transition_noop_hook(0x1f, 1);
    sep_runtime_feature_flags_validate_platform_support(&flags);
    sep_runtime_provider_context_ready_hook(
        (const void *)(uintptr_t)provider_context
    );

    sep_u64 base = 0;
    sep_size_t length = 0;
    sep_runtime_region_get_layout(&base, &length, 3);
    sep_runtime_region_get_layout(&base, &length, 1);
#ifndef OPEN_SECURE_ROM_HOST_TEST
    __asm__ volatile("dsb sy" ::: "memory");
#endif
    sep_runtime_regions_commit_barrier_hook();
    sep_platform_runtime_authentication_finalize_noop();
    sep_boot_prepare_runtime_mapping_and_panic_on_return(1);
}
