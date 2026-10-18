# SEP firmware keys

The SEP firmware payload inside `sep-firmware.*.im4p` is AES-256-CBC
encrypted with a per-image IV and key. OpenSEP decrypts it itself, so it needs
the right pair for the image the host hands it. This note covers where the
keys come from today, how they can be fetched, and the planned move of the
keys out of the ROM.

## How the ROM picks a key today

`src/platform/platform.c:321` holds a table of `{iv[16], key[32]}` rows.
Nothing in the image names its key, so the ROM tries each row on the
payload's first block and keeps the one that yields the expected reset
prologue (`sep_shared_image_select_payload_keybag_for_payload`, called from
`src/runtime/runtime_transfer.c:165`; the decrypt itself is at
`src/runtime/runtime_transfer.c:187`). Adding a build means appending a row;
earlier builds keep matching the row they always did.

## Where the keys come from

All rows are publicly published keys for iPhone14,4 (d16) and were checked
byte for byte against The Apple Wiki:

| Row | Build | iOS | Wiki page |
|---|---|---|---|
| 0 | 21A329 | 17.0 | `Keys:Dawn_21A329_(iPhone14,4)` |
| 1 | 19A348 | 15.0.1 | `Keys:Sky_19A348_(iPhone14,4)` |
| 2 | 24A437 | 27.0 | `Keys:Rave_24A437_(iPhone14,4)` |
| 3 | 20A362 | 16.0 | `Keys:Sydney_20A362_(iPhone14,4)` |
| 4 | 23A341 | 26.0 | `Keys:Luck_23A341_(iPhone14,4)` |
| 5 | 22G100 | 18.6.2 | `Keys:CrystalG_22G100_(iPhone14,4)` |

### Fetching from The Apple Wiki

The wiki runs a standard MediaWiki API. Page titles carry the build's
codename, so search first, then read the `{{keys}}` template:

```
# 1. find the page for a build and device
https://theapplewiki.com/api.php?action=query&list=search&srsearch=intitle:"19A348 (iPhone14,4)"&srnamespace=*&format=json
# 2. read its wikitext and take SEPFirmwareIV / SEPFirmwareKey
https://theapplewiki.com/api.php?action=parse&page=Keys:Sky_19A348_(iPhone14,4)&prop=wikitext&format=json
```

The relevant template fields:

```
 | SEPFirmware           = sep-firmware.d16.RELEASE.im4p
 | SEPFirmwareIV         = <32 hex digits>
 | SEPFirmwareKey        = <64 hex digits>
```

### Sources that do not have them

- **AppleDB** (`api.appledb.dev`): its per-build JSON has `decryptionKey`
  fields, but those are AEA archive keys for OTA/IPSW downloads, not the IV
  and key of individual `.im4p` images.
- **api.ipsw.me**: the old `/v4/keys/...` endpoints return 404.

## Planned: keys supplied by the host

The intent is to remove the table from the ROM and have the host hand the ROM
its candidate keys at boot, in the same spirit as the boot ROM's patch store
(a sealed blob at a fixed address). Because the ROM already selects by trial
decryption, the host only has to supply candidates; it does not need to know
which one is right.

Host-side lookup order:

1. A user-maintained property list, for example
   `~/.config/opensep/keys.plist`, keyed by build, with `SEPFirmwareIV` and
   `SEPFirmwareKey` string fields (the wiki's field names).
2. The Apple Wiki API as above, with the answer written back to a local cache.
3. For builds the wiki lacks (betas, new releases), ask the user to add an
   entry to the plist.

This changes the contract between the ROM and its host, so it lands together
with the emulator side and needs a boot run on each supported iOS version
before it replaces the built-in table.
