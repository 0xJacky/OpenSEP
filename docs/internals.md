# Internals

## Toolchain

| Tool | Used for |
| --- | --- |
| LLVM `clang`, `llvm-objcopy`, `llvm-readobj`, `llvm-ar` (`/opt/homebrew/opt/llvm/bin`, override with `LLVM_PREFIX=`) | cross-compiling the ROM |
| `ld.lld` (`/opt/homebrew/bin/ld.lld`) | linking the ROM against `linker.ld` |
| host `clang` (override with `HOST_CC=`) | building the host test binaries |
| `make` | the build |
| `uv` (with a Python 3) | running `tools/verify_coverage.py` |
| `rg` (ripgrep) | the relocation gate in `make verify` |

Nothing outside this repository is needed to build or verify.

## Verification

Each `tests/**/<name>_tests.c` builds to `build/<name>_tests` against a host
build of the same sources (`-DOPEN_SECURE_ROM_HOST_TEST`).

`make verify` also runs these gates on the ROM:

- the linker script fixes the entry at `0x02000000`, the early vectors at
  `+0x800` and the runtime vectors at `+0x4000`, and enforces the ROM/RAM
  layout of the interface;
- the flat image must not exceed `0x29000` bytes;
- the ELF must carry no relocations.

Two optional inputs extend it; without them the corresponding step says so
and passes:

- `OPENSEP_SEPFW_IMAGE` names a real personalised SEP firmware image
  (`RestoreSEP.img4`, e.g. from 21A329) for `sepfw_tests`, which decodes it on
  the host exactly as the ROM would.
- `OPENSEP_RESEARCH_DIR` names a directory containing
  `symbols/recovered-function-prototypes.json`, `evidence/functions.json` and
  `include/sep_recovered_types.h`. With it, `tools/verify_coverage.py` runs
  an optional compatibility check of OpenSEP's `sep_*` function signatures
  against that reference list of the ROM interface's entry points. The
  reference list is not distributed here.


## Source layout

Implementation sources and tests mirror subsystem ownership:

```text
src/                         tests/
├── crypto/                  ├── crypto/
│   ├── aes/                 │   ├── aes/
│   ├── cmac/                │   ├── cmac/
│   ├── hash/                │   ├── hash/
│   ├── bignum/              │   ├── bignum/
│   ├── ecc/                 │   ├── ecc/
│   ├── rsa/                 │   ├── rsa/
│   └── support/             │   └── support/
├── image/                   ├── image/
│   ├── der/                 │   ├── der/
│   ├── img4/                │   ├── img4/
│   └── shared/              │   └── shared/
├── runtime/                 ├── runtime/
├── platform/                ├── platform/
└── protocol/                └── protocol/
```

Primary public declarations follow the same hierarchy under
`include/open_secure_rom` (the project's former name, kept for the C
identifiers). Compatibility forwarding headers preserve existing includes
such as `open_secure_rom/aes.h` and `open_secure_rom/runtime.h`. The Makefile
discovers C and assembly implementations recursively.

