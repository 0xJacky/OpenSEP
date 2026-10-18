#include "open_secure_rom/shared_image.h"

#include "open_secure_rom/img4.h"
#include "open_secure_rom/optional_values.h"
#include "open_secure_rom/panic.h"

static void shared_image_require_context(
    const sep_shared_image_context_t *context
) {
    if (context == NULL || ((uintptr_t)context & 7U) != 0) {
        sep_panic_reason_1a();
    }
}

int sep_shared_image_property_callback(
    sep_u64 property_tag,
    sep_der_item_t *property,
    sep_u32 dictionary_kind,
    sep_shared_image_context_t *context
) {
    shared_image_require_context(context);
    sep_shared_image_properties_t *properties =
        (sep_shared_image_properties_t *)context;

    switch ((sep_u32)property_tag) {
    case 0x414d4e4dU:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(288, 0);
        if (!sep_img4_manifest_require_boolean_property(property, 0x414d4e4dU)) return 0;
        sep_shared_image_properties_mark_amnm(properties);
        return 0;
    case 0x424f5244U:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(208, 0);
        sep_shared_image_properties_set_bord(
            properties,
            sep_img4_require_property_integer64(property, 0x424f5244U)
        );
        return 0;
    case 0x7569646dU:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(224, 0);
        sep_shared_image_properties_set_uidm(
            properties,
            sep_img4_manifest_require_boolean_property(property, 0x7569646dU)
        );
        return 0;
    case 0x43484950U:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(200, 0);
        sep_shared_image_properties_set_chip(
            properties,
            sep_img4_require_property_integer64(property, 0x43484950U)
        );
        return 0;
    case 0x4350524fU:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(216, 0);
        sep_shared_image_properties_set_cpro(
            properties,
            sep_img4_manifest_require_boolean_property(property, 0x4350524fU)
        );
        return 0;
    case 0x43534543U:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(220, 0);
        sep_shared_image_properties_set_csec(
            properties,
            sep_img4_manifest_require_boolean_property(property, 0x43534543U)
        );
        return 0;
    case 0x45434944U:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(204, 0);
        sep_shared_image_properties_set_ecid(
            properties,
            sep_img4_require_property_integer64(property, 0x45434944U)
        );
        return 0;
    case 0x53444f4dU:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(212, 0);
        sep_shared_image_properties_set_sdom(
            properties,
            sep_img4_require_property_integer64(property, 0x53444f4dU)
        );
        return 0;
    case 0x4345504fU:
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(196, 0);
        sep_shared_image_properties_set_cepo(
            properties,
            sep_img4_require_property_integer64(property, 0x4345504fU)
        );
        return 0;
    case 0x6573646dU: {
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(306, 0);
        const sep_u64 value = sep_img4_require_property_integer64(
            property,
            0x6573646dU
        );
        if (value >= 0x100) sep_panic_reason_2a();
        sep_shared_image_properties_set_esdm(properties, (sep_u8)value);
        return 0;
    }
    case 0x736e6f6eU: {
        if (dictionary_kind != 0) sep_panic_with_reason_and_pc(278, 0);
        const sep_u8 *data = NULL;
        sep_u32 length = 0;
        const int result = sep_img4_decode_get_property_data(
            property,
            0x736e6f6eU,
            &data,
            &length
        );
        if (result != 0) return result;
        const sep_checked_bytes20_t nonce =
            sep_checked_bytes20_from_data(data, length);
        sep_shared_image_properties_set_snon(properties, &nonce);
        return 0;
    }
    case 0x44475354U:
    case 0x6f707064U: {
        if (dictionary_kind != 1) {
            sep_panic_with_reason_and_pc(
                (sep_u32)property_tag == 0x44475354U ? 256 : 267,
                0
            );
        }
        const sep_u8 *data = NULL;
        sep_u32 length = 0;
        const int result = sep_img4_decode_get_property_data(
            property,
            property_tag,
            &data,
            &length
        );
        if (result != 0) return result;
        const sep_checked_bytes48_t digest =
            sep_checked_bytes48_from_data(data, length);
        if ((sep_u32)property_tag == 0x44475354U) {
            sep_shared_image_properties_set_dgst(properties, &digest);
        } else {
            sep_shared_image_properties_set_oppd(properties, &digest);
        }
        return 0;
    }
    case 0x44534543U:
        if (dictionary_kind != 1) sep_panic_with_reason_and_pc(293, 0);
        if (!sep_img4_manifest_require_boolean_property(property, 0x44534543U)) return 0;
        sep_shared_image_properties_mark_dsec(properties);
        return 0;
    case 0x454b4559U:
        if (dictionary_kind != 1) sep_panic_with_reason_and_pc(228, 0);
        sep_shared_image_properties_set_ekey(
            properties,
            sep_img4_manifest_require_boolean_property(property, 0x454b4559U)
        );
        return 0;
    case 0x4550524fU:
        if (dictionary_kind != 1) sep_panic_with_reason_and_pc(298, 0);
        sep_shared_image_properties_set_epro(
            properties,
            sep_img4_manifest_require_boolean_property(property, 0x4550524fU)
        );
        return 0;
    case 0x45534543U:
        if (dictionary_kind != 1) sep_panic_with_reason_and_pc(302, 0);
        sep_shared_image_properties_set_esec(
            properties,
            sep_img4_manifest_require_boolean_property(property, 0x45534543U)
        );
        return 0;
    case 0x65673074U:
    case 0x65673174U:
    case 0x65673374U:
    case 0x6567306eU:
    case 0x6567316eU:
    case 0x6567336eU: {
        if (dictionary_kind != 1) {
            const sep_u32 reasons[6] = {232, 236, 240, 244, 248, 252};
            const sep_u32 tags[6] = {
                0x65673074U, 0x65673174U, 0x65673374U,
                0x6567306eU, 0x6567316eU, 0x6567336eU,
            };
            sep_u32 index = 0;
            while (tags[index] != property_tag) ++index;
            sep_panic_with_reason_and_pc(reasons[index], 0);
        }
        const sep_bool value = sep_img4_manifest_require_boolean_property(
            property,
            (sep_u32)property_tag
        );
        switch ((sep_u32)property_tag) {
        case 0x65673074U: sep_shared_image_properties_set_eg0t(properties, value); break;
        case 0x65673174U: sep_shared_image_properties_set_eg1t(properties, value); break;
        case 0x65673374U: sep_shared_image_properties_set_eg3t(properties, value); break;
        case 0x6567306eU: sep_shared_image_properties_set_eg0n(properties, value); break;
        case 0x6567316eU: sep_shared_image_properties_set_eg1n(properties, value); break;
        default: sep_shared_image_properties_set_eg3n(properties, value); break;
        }
        return 0;
    }
    default:
        return 0;
    }
}
