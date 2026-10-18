# Open items

Work that is known and deliberately deferred. Each item changes the ROM image
or its contract with the host, so each needs a boot run on every supported
iOS version before it is merged.

## Platforms

- **t8110 regression.** The `t8110` row reproduces the handoff this ROM
  used to make unconditionally, and `boot_handoff_tests` pins its values.
  It has not yet been booted on the iphone-cli QEMU machine since the table
  was introduced. Run a 15.0.1 (19A348) round with `make PLATFORM=t8110`
  before iphone-cli takes this version.
- **Warm boot and run-time selection**: see the end of
  [platforms.md](platforms.md).

## Keys out of the ROM

Move the SEP firmware key table from `src/platform/platform.c` to the host.
Design and key sources: [sep-firmware-keys.md](sep-firmware-keys.md).

## AKE random number generator

`src/protocol/security/ake_state.c:160-173`: the AKE layer is wired to
`sep_ake_get_zero_rng_state`, whose generator fills its output with zeros.
Nothing outside `src/protocol/security/` calls into AKE today (opcode `0x05`
only publishes a ready tag), so this has no effect on the current boot path.
**Before AKE is connected to anything, it must get a real entropy source**;
with this generator every ephemeral key would be predictable.

## Crypto layer

The crypto under `src/crypto/` is written for this project and named after
the routines the SEP ROM interface uses (`sep_cc*`, workspace-style `_ws`
functions). Options considered for the future:

- **Rename only.** Move the `sep_cc*` names to the project's own convention.
  No size change. The optional signature check in `tools/verify_coverage.py`
  compares these names and would need updating.
- **An established library.** The ROM window is `ROM_LIMIT = 0x02029000`
  (`linker.ld:4`), 167,936 bytes, of which about 148 KB is used — roughly
  20 KB free.
  - **BearSSL** (MIT) fits best: no heap, constant-time, small P-384 and
    RSA up to 4096, HMAC/HKDF/CCM/CBC. It lacks CMAC (about 60 lines on its
    CBC-MAC) and SHA-3.
  - **Mbed TLS / TF-PSA-Crypto** (Apache-2.0, already vendored by OpenAVB):
    about size-neutral (~54 KB for everything OpenSEP uses vs ~55 KB now),
    but needs a heap (16 KB of free SEP RAM would do, e.g.
    `0x04024000`–`0x04028000`) and hand-written HKDF and SP 800-108
    CTR-CMAC KDF, which TF-PSA-Crypto only exposes through its PSA core.
  - **OpenSSL** is not an option: it needs a libc and is hundreds of KB.

  Every primitive here is deterministic by specification (SHA, HMAC, AES,
  CMAC, CCM, RSA verify, the ECDH shared secret), so a swap changes code
  addresses and sizes but no byte that leaves the ROM. What breaks is
  internal: the fault-canary tests, the context-size `_Static_assert`s, and
  the callers that size buffers from the current context macros
  (`ake_*.c`, `img4_decode.c`, `runtime_transfer.c`). Do the live boot path
  first (hashes, HMAC, AES-CBC), ECC and AKE last.
