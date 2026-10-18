#include "open_secure_rom/x509.h"

#include <assert.h>

static void test_find_extension(void) {
    static const sep_u8 encoded[] = {
        0x30, 0x18,
        0x30, 0x16,
        0x06, 0x0a,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0f,
        0x01, 0x01, 0xff,
        0x04, 0x05, 0x31, 0x03, 0x02, 0x01, 0x05,
    };
    sep_x509_certificate_t certificate = {0};
    certificate.fields[9].data = encoded;
    certificate.fields[9].length = sizeof(encoded);
    sep_der_item_t extension;
    assert(sep_x509_find_img4_certificate_extension(
        &certificate,
        &extension
    ) == 0);
    assert(extension.length == 5);
    assert(extension.data[0] == 0x31);
    assert(extension.data[4] == 0x05);
}

static void test_optional_absence_and_missing_oid(void) {
    sep_x509_certificate_t certificate = {0};
    sep_der_item_t extension = {(const sep_u8 *)1, 1};
    assert(sep_x509_find_img4_certificate_extension(
        &certificate,
        &extension
    ) == 0);
    assert(extension.data == 0 && extension.length == 0);

    static const sep_u8 encoded[] = {
        0x30, 0x13,
        0x30, 0x11,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x01,
        0x04, 0x05, 0x31, 0x03, 0x02, 0x01, 0x05,
    };
    certificate.fields[9].data = encoded;
    certificate.fields[9].length = sizeof(encoded);
    assert(sep_x509_find_img4_certificate_extension(
        &certificate,
        &extension
    ) == 0);
    assert(extension.data == 0 && extension.length == 0);
}

static void test_rejects_malformed_extension_value(void) {
    static const sep_u8 encoded[] = {
        0x30, 0x15,
        0x30, 0x13,
        0x06, 0x0a,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0f,
        0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05,
    };
    sep_x509_certificate_t certificate = {0};
    certificate.fields[9].data = encoded;
    certificate.fields[9].length = sizeof(encoded);
    sep_der_item_t extension;
    assert(sep_x509_find_img4_certificate_extension(
        &certificate,
        &extension
    ) == -1);
}

int main(void) {
    test_find_extension();
    test_optional_absence_and_missing_oid();
    test_rejects_malformed_extension_value();
    return 0;
}
