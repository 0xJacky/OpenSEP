#ifndef OPEN_SECURE_ROM_X509_H
#define OPEN_SECURE_ROM_X509_H

#include "open_secure_rom/img4.h"

int sep_x509_find_img4_certificate_extension(
    const sep_x509_certificate_t *certificate,
    sep_der_item_t *extension_value
);

#endif
