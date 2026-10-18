#ifndef OPEN_SECURE_ROM_SHARED_IMAGE_H
#define OPEN_SECURE_ROM_SHARED_IMAGE_H

#include "open_secure_rom/der.h"

void sep_shared_image_properties_initialize(
    sep_shared_image_properties_t *properties
);
void sep_shared_image_properties_initialize_fields(
    sep_shared_image_properties_t *properties
);
void sep_shared_image_context_set_mode(
    sep_shared_image_context_t *context,
    sep_u8 mode
);
void sep_shared_image_context_set_payload_type(
    sep_shared_image_context_t *context,
    sep_u32 payload_type
);
sep_u8 sep_shared_image_context_mode_checked(
    const sep_shared_image_context_t *context
);
sep_u32 sep_shared_image_context_payload_type_checked(
    const sep_shared_image_context_t *context
);
sep_optional_configuration_key48_t
sep_shared_image_context_get_optional_key48(
    const sep_shared_image_context_t *context
);
void sep_shared_image_auxiliary_initialize(
    sep_shared_image_auxiliary_t *auxiliary
);
void sep_shared_image_auxiliary_initialize_fields(
    sep_shared_image_auxiliary_t *auxiliary
);
sep_shared_image_auxiliary_keybag_entry_t *
sep_shared_image_auxiliary_keybag_entry_at(
    sep_shared_image_auxiliary_t *auxiliary,
    sep_u32 index
);
void sep_shared_image_payload_keybag_initialize_absent(
    sep_shared_image_payload_keybag_t *keybag
);
void sep_shared_image_payload_keybag_initialize_fields(
    sep_shared_image_payload_keybag_t *keybag
);
void sep_shared_image_properties_set_manifest_digest(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *digest
);
void sep_shared_image_properties_set_cepo(
    sep_shared_image_properties_t *properties,
    sep_u64 value
);
void sep_shared_image_properties_set_chip(
    sep_shared_image_properties_t *properties,
    sep_u64 value
);
void sep_shared_image_properties_set_ecid(
    sep_shared_image_properties_t *properties,
    sep_u64 value
);
void sep_shared_image_properties_set_bord(
    sep_shared_image_properties_t *properties,
    sep_u64 value
);
void sep_shared_image_properties_set_sdom(
    sep_shared_image_properties_t *properties,
    sep_u64 value
);
void sep_shared_image_properties_set_cpro(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_csec(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_uidm(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_ekey(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_eg0t(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_eg1t(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_eg3t(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_eg0n(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_eg1n(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_eg3n(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_dgst(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *digest
);
void sep_shared_image_properties_set_oppd(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *digest
);
void sep_shared_image_properties_set_snon(
    sep_shared_image_properties_t *properties,
    const sep_checked_bytes20_t *nonce
);
void sep_shared_image_properties_mark_amnm(
    sep_shared_image_properties_t *properties
);
void sep_shared_image_properties_mark_dsec(
    sep_shared_image_properties_t *properties
);
void sep_shared_image_properties_set_epro(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_esec(
    sep_shared_image_properties_t *properties,
    sep_bool value
);
void sep_shared_image_properties_set_esdm(
    sep_shared_image_properties_t *properties,
    sep_u8 value
);
sep_bool sep_shared_image_properties_ekey_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_eg0t_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_eg1t_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_eg3t_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_eg0n_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_eg1n_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_eg3n_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_amnm_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_dsec_checked(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_has_oppd(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_has_dgst(
    const sep_shared_image_properties_t *properties
);
sep_bool sep_shared_image_properties_oppd_matches_if_present(
    const sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *expected
);
sep_bool sep_shared_image_properties_dgst_matches_if_present(
    const sep_shared_image_properties_t *properties,
    const sep_checked_bytes48_t *expected
);
sep_bool sep_shared_image_payload_keybag_is_present_and_allowed(
    const sep_shared_image_context_t *context,
    sep_bool allow_unrestricted
);
sep_bool sep_shared_image_strict_policy_is_enabled(void);
sep_bool sep_shared_image_validate_platform_constraints(
    const sep_shared_image_context_t *context
);
sep_shared_image_research_policy_t
sep_shared_image_evaluate_research_policy(
    const sep_shared_image_context_t *context
);
void __attribute__((noreturn)) sep_shared_image_research_policy_panic(
    sep_shared_image_research_policy_t status
);
sep_shared_image_context_t sep_shared_image_decode_and_evaluate(
    sep_u32 mode,
    const sep_u8 *image,
    sep_size_t image_length
);
int sep_shared_image_property_callback(
    sep_u64 property_tag,
    sep_der_item_t *property,
    sep_u32 dictionary_kind,
    sep_shared_image_context_t *context
);
sep_shared_image_payload_keybag_t sep_shared_image_select_payload_keybag(
    const sep_shared_image_auxiliary_t *auxiliary
);
sep_shared_image_payload_keybag_t
sep_shared_image_select_payload_keybag_for_payload(
    const sep_shared_image_auxiliary_t *auxiliary,
    const void *ciphertext,
    sep_size_t ciphertext_length
);

#endif
