#include "open_secure_rom/boot_handoff.h"

#include "open_secure_rom/boot_platform.h"
#include "open_secure_rom/protocol.h"
#include "open_secure_rom/runtime.h"
#include "open_secure_rom/runtime_handoff.h"
#include "open_secure_rom/runtime_storage.h"
#include "open_secure_rom/shared_image.h"

enum {
    BOOT_PANIC_ARITHMETIC_OVERFLOW = 0x1c,
    BOOT_PANIC_LENGTH_EXCEEDS_U32 = 0x2a,
    BOOT_PANIC_REGION_TABLE_ADDRESS = 0x2f,
    BOOT_PANIC_REGION_LENGTH_EXCEEDS_U32 = 0x3b,
    BOOT_PANIC_RUNTIME_MODE = 0x49,
    BOOT_PANIC_HANDOFF_CAPACITY = 0x53,
    BOOT_PANIC_IMAGE_MODE = 0x84,
    BOOT_PANIC_EMPTY_PATTERN = 0x92,
    BOOT_PANIC_FINAL_RUNTIME_MODE = 0x9b,
};

typedef struct boot_handoff_plan {
    sep_size_t aligned_offset;
    sep_u64 runtime_destination;
    sep_size_t runtime_region_length;
} boot_handoff_plan_t;

static void __attribute__((noreturn)) boot_handoff_panic(sep_u32 reason) {
#ifdef OPEN_SECURE_ROM_HOST_TEST
    open_secure_rom_boot_handoff_test_panic(reason);
#else
    (void)reason;
    sep_fatal_wait_loop();
#endif
}

static sep_size_t checked_add_size(sep_size_t left, sep_size_t right) {
    if (left > SIZE_MAX - right) {
        boot_handoff_panic(BOOT_PANIC_ARITHMETIC_OVERFLOW);
    }
    return left + right;
}

static sep_u64 checked_add_u64(sep_u64 left, sep_u64 right) {
    if (left > UINT64_MAX - right) {
        boot_handoff_panic(BOOT_PANIC_ARITHMETIC_OVERFLOW);
    }
    return left + right;
}

const sep_address_range_t *sep_boot_runtime_region_at(
    sep_size_t table_index
) {
    if (table_index > UINT32_MAX) {
        boot_handoff_panic(BOOT_PANIC_REGION_TABLE_ADDRESS);
    }
    return sep_runtime_region_at_checked((sep_u32)table_index);
}

sep_size_t sep_boot_runtime_region_length(sep_size_t table_index) {
    return sep_address_range_length(sep_boot_runtime_region_at(table_index));
}

/*
 * Where the runtime is entered, in the SEP's own view.  A platform that names
 * the address gets it; otherwise it is region one's base plus the mode's
 * offset, which is what AVPSEPBooter computes.
 */
sep_u64 sep_boot_runtime_destination_base(sep_u32 runtime_mode) {
    const sep_u64 runtime_entry = sep_boot_platform()->runtime_entry;
    if (runtime_entry != 0) {
        return runtime_entry;
    }
    return sep_runtime_region_mode_base(1, runtime_mode);
}

sep_boot_runtime_entry_t sep_boot_runtime_entry(
    sep_u64 handoff_address,
    sep_u32 runtime_mode
) {
    const sep_boot_platform_t *const platform = sep_boot_platform();
    const sep_u64 address = sep_boot_runtime_destination_base(runtime_mode);
    sep_boot_runtime_entry_t entry = {
        .address = address,
        .x0 = handoff_address,
    };
    if (platform->cold_input_offset != 0) {
        entry.x1 = checked_add_u64(address, platform->cold_input_offset);
    }
    if (platform->handoff_in_power_down_register) {
        entry.x0 = handoff_address | 1u;
        entry.power_down_save = entry.x0;
    }
    return entry;
}

static boot_handoff_plan_t make_handoff_plan(
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
) {
    const sep_size_t runtime_region_length =
        sep_boot_runtime_region_length(1);
    if (runtime_region_length >= UINT32_MAX) {
        boot_handoff_panic(BOOT_PANIC_REGION_LENGTH_EXCEEDS_U32);
    }

    sep_size_t capacity;
    switch (runtime_mode) {
    case 1:
        capacity = sep_boot_runtime_region_length(2);
        break;
    case 3:
        capacity = sep_boot_runtime_region_length(3);
        break;
    case 4:
        capacity = runtime_region_length;
        break;
    default:
        boot_handoff_panic(BOOT_PANIC_RUNTIME_MODE);
    }

    const sep_size_t content_length = checked_add_size(
        payload_length,
        manifest_length
    );
    const sep_size_t aligned_offset = checked_add_size(content_length, 63) &
        ~(sep_size_t)63;
    const sep_size_t total_length = checked_add_size(
        aligned_offset,
        SEP_BOOT_RUNTIME_HANDOFF_SIZE
    );
    if (total_length > capacity) {
        boot_handoff_panic(BOOT_PANIC_HANDOFF_CAPACITY);
    }

    const sep_u64 runtime_destination =
        sep_boot_runtime_destination_base(4);
    return (boot_handoff_plan_t){
        .aligned_offset = aligned_offset,
        .runtime_destination = runtime_destination,
        .runtime_region_length = runtime_region_length,
    };
}

static sep_u64 build_runtime_handoff(
    sep_boot_runtime_handoff_t *output,
    sep_size_t *aligned_offset,
    const sep_shared_image_context_t *image,
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
) {
    const boot_handoff_plan_t plan = make_handoff_plan(
        payload_length,
        manifest_length,
        runtime_mode
    );
    const sep_u32 payload_type =
        sep_shared_image_context_payload_type_checked(image);

    sep_memzero(output, sizeof(*output));
    output->magic = SEP_BOOT_RUNTIME_HANDOFF_MAGIC;
    output->version = SEP_BOOT_RUNTIME_HANDOFF_VERSION;
    output->header_size = SEP_BOOT_RUNTIME_HANDOFF_SIZE;
    output->runtime_destination = plan.runtime_destination;
    output->payload_type = payload_type;

    const sep_optional_configuration_key48_t optional_key =
        sep_shared_image_context_get_optional_key48(image);
    if (optional_key.present > 1) {
        sep_fatal_wait_loop();
    }
    if (optional_key.present) {
        output->optional_key_present = 1;
        sep_memmove(
            output->optional_key,
            optional_key.bytes,
            sizeof(output->optional_key)
        );

        const sep_u8 image_mode =
            sep_shared_image_context_mode_checked(image);
        if (image_mode == 1) {
            output->authorization_flag = 1;
        } else if (image_mode == 0) {
            output->authorization_flag =
                sep_shared_image_properties_amnm_checked(
                    (const sep_shared_image_properties_t *)image
                ) == 0;
        } else {
            boot_handoff_panic(BOOT_PANIC_IMAGE_MODE);
        }
    }

    if (payload_length > UINT32_MAX || manifest_length > UINT32_MAX) {
        boot_handoff_panic(BOOT_PANIC_LENGTH_EXCEEDS_U32);
    }
    output->payload_length = (sep_u32)payload_length;
    output->manifest_length = (sep_u32)manifest_length;

    sep_fill_research_seed_pattern(
        output->research_pattern,
        sizeof(output->research_pattern)
    );
    if (!sep_buffer_has_nonzero_byte(
        output->research_pattern,
        sizeof(output->research_pattern)
    )) {
        boot_handoff_panic(BOOT_PANIC_EMPTY_PATTERN);
    }
    sep_platform_copy_runtime_handoff_metadata(
        output->platform_metadata,
        sizeof(output->platform_metadata)
    );

    if (runtime_mode != 4) {
        boot_handoff_panic(BOOT_PANIC_FINAL_RUNTIME_MODE);
    }
    const sep_u64 handoff_address = checked_add_u64(
        plan.runtime_destination,
        plan.aligned_offset
    );
    const sep_u32 runtime_region_length =
        sep_boot_platform()->runtime_region_length;
    if (runtime_region_length != 0) {
        output->runtime_region_length = runtime_region_length;
    } else {
        output->runtime_region_length = (sep_u32)(
            plan.runtime_region_length > SEP_BOOT_RUNTIME_REGION_LENGTH_CAP
                ? SEP_BOOT_RUNTIME_REGION_LENGTH_CAP
                : plan.runtime_region_length
        );
    }
    *aligned_offset = plan.aligned_offset;
    return handoff_address;
}

sep_u64 open_secure_rom_build_runtime_handoff_header(
    sep_boot_runtime_handoff_t *output,
    const sep_shared_image_context_t *image,
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
) {
    sep_size_t aligned_offset;
    return build_runtime_handoff(
        output,
        &aligned_offset,
        image,
        payload_length,
        manifest_length,
        runtime_mode
    );
}


/*
 * The two translation tables the runtime turns its MMU on with.
 *
 * It takes their bases out of the block at `runtime_destination + 0x20000`:
 *
 *     ldp x8, x9, [x0, #0x68]      -> TTBR0_EL1, TTBR1_EL1 (ASID 0xFF)
 *     TCR_EL1 = 0x0100_0001_6520_A51C
 *
 * which is a sixteen kilobyte granule with T0SZ 28 and T1SZ 32, so both
 * lookups start at level two with thirty-two megabyte blocks: 2048 entries
 * span the low thirty-six bits, and 128 span the top four gigabytes.
 *
 * The high half is the point of the exercise.  Straight after enabling the
 * MMU the runtime sets VBAR to 0xFFFF_FFFF_0000_4800 and jumps to
 * 0xFFFF_FFFF_0000_9610 -- the instruction after the call, at its linked
 * address -- so it is linked at 0xFFFF_FFFF_0000_0000 and mapped
 *
 *     0xFFFF_FFFF_0000_0000 + offset  ->  runtime_destination + offset
 *
 * Only this side of the handoff knows where the image was put, which is why
 * only this side can build that.  The low half is the identity, because the
 * runtime keeps reaching registers by their machine addresses -- 0x2_5C20_0000
 * among them -- after the MMU is on.
 *
 * The tables go above the block and below the stack the runtime starts on,
 * which it sets to `runtime_destination + 0x34000`.  Everything from 0x15000
 * to 0x74000 is a hole in the image, so nothing of the runtime's is being
 * written over; 0x1c000 is spoken for (the resume path copies into it) and the
 * block itself runs to at least 0x22548, which is what leaves 0x24000.
 */
enum {
    /*
     * The tables live in the region's tail, past anything the image reaches.
     * They used to sit in the image's hole, which also holds the stacks and
     * the per-core structures; there is no need to crowd it.
     */
    BOOT_TABLE_TTBR0_OFFSET = 0x1F00000,
    BOOT_TABLE_TTBR1_OFFSET = 0x1F04000,
    BOOT_TABLE_SIZE = 0x4000,
    BOOT_TABLE_ENTRIES = BOOT_TABLE_SIZE / 8,
    BOOT_TABLE_BLOCK_SHIFT = 25,          /* thirty-two megabytes */
    BOOT_TABLE_HIGH_ENTRIES = 128,        /* four gigabytes of them */
    /* A level two block: valid, inner shareable, accessed, MAIR index zero. */
    BOOT_TABLE_BLOCK_FLAGS = (1ULL << 10) | (3ULL << 8) | 1ULL,
    /*
     * Read-only at EL1, which is what makes it executable.
     *
     * The runtime sets SCTLR_EL1.WXN the moment it is running at its linked
     * address -- `SCTLR |= 0x80000` in the first function it reaches -- and
     * that makes every region writable at EL1 execute-never.  Mapped writable,
     * the very next instruction fetch faults, which is the whole of what
     * `0xFFFF_FFFF_0000_4A00` was.  So the half it executes out of is
     * read-only and the half it keeps its stacks and per-core state in is not.
     */
    BOOT_TABLE_READ_ONLY = 2ULL << 6,
    /* And what it writes is never executed from, so say so. */
    BOOT_TABLE_NEVER_EXECUTE = 1ULL << 53,

    /*
     * Sixteen kilobyte pages, because thirty-two megabyte blocks cannot say
     * two different things about one region and this one needs to.
     *
     * Measured, with the trap in the runtime's own vector: mapped writable the
     * instruction fetch of the vector faults, because WXN; mapped read-only
     * the *write* faults -- ESR 0x9600_004E, a level two permission fault on a
     * store, FAR 0xFFFF_FFFF_0002_1088, which is the per-core structure at
     * 0x20FC8, written by the runtime's early per-core setup.  It executes and writes through the same high
     * addresses, so the split has to be by page.
     *
     * What it writes is the hole in its own image -- the block at 0x20000, the
     * per-core structures just after it, the stacks up to 0x34000 -- and that
     * hole is 0x15000 to 0x74000, rounded out to the page.
     */
    BOOT_TABLE_L3_LOW_OFFSET = 0x1F08000,
    BOOT_TABLE_L3_HIGH_OFFSET = 0x1F0C000,
    BOOT_TABLE_PAGE_SHIFT = 14,
    BOOT_TABLE_PAGE = 1 << BOOT_TABLE_PAGE_SHIFT,
    BOOT_TABLE_L3_ENTRIES = BOOT_TABLE_SIZE / 8,
    BOOT_TABLE_DATA_FIRST = 0x14000 >> BOOT_TABLE_PAGE_SHIFT,
    BOOT_TABLE_DATA_LIMIT = 0x74000 >> BOOT_TABLE_PAGE_SHIFT,
    /* A level three page, as against a level two block. */
    BOOT_TABLE_PAGE_FLAGS = (1ULL << 10) | (3ULL << 8) | 3ULL,
    /* A level two entry that points at one of those tables. */
    BOOT_TABLE_NEXT_LEVEL = 3ULL,

    /* The platform register window, and where in the high half it lands. */
    BOOT_TABLE_PLATFORM_SLOT = 120,
};

#define BOOT_PLATFORM_PHYSICAL 0x25C000000ULL
#define BOOT_PLATFORM_VIRTUAL  0xFFFFFFFFF0200000ULL

/* Where this ROM sees the runtime region; see the mapping for mode four. */
#define BOOT_RUNTIME_WINDOW 0x0800000000ULL

/*
 * Where the t8110 runtime's cold path builds its own copy of the handoff
 * (image + 0x20000, compiled into the runtime); write_runtime_tables
 * points the copy's table fields at the tables.
 */
#define BOOT_HANDOFF_OFFSET 0x20000ULL

/*
 * Whether to leave the state a suspend would have.
 *
 * Off, and it has to stay off unless something needs the resume arm: the only
 * function that reads these -- the runtime's power-state check, block+0x5C0
 * and the magic at image+0x14800 -- is reached from the *resume* entry, and writing them was
 * what put this ROM on that arm in the first place.  Their real producer is
 * the cold path, so with them written by hand there is no way to tell whether
 * it produced them.
 */
#ifndef OPEN_SECURE_ROM_FORCE_SUSPEND_STATE
#define OPEN_SECURE_ROM_FORCE_SUSPEND_STATE 0
#endif

/* A debugging aid; see where it is used. */
#ifndef OPEN_SECURE_ROM_TRAP_RUNTIME_ENTRY
#define OPEN_SECURE_ROM_TRAP_RUNTIME_ENTRY 0
#endif
#ifndef OPEN_SECURE_ROM_TRAP_RUNTIME_FAULT
#define OPEN_SECURE_ROM_TRAP_RUNTIME_FAULT 1
#endif
#ifndef OPEN_SECURE_ROM_TRAP_VECTOR
/*
 * Which vector slot to replace.
 *
 * 0xA00 while the cold path is still early: the runtime's entry installs the
 * table at image+0x800 first and only swaps in its real one (0x4800) once it
 * is further along, so a fault before that lands at 0x800+0x200 -- in a table
 * whose every slot is `b .`, which is why it shows up as a core parked at
 * image+0xA00 with nothing to read.
 *
 * 0x4A00 is the slot to use once it has got past this, and each of the three
 * candidates was tried.  The runtime's entry installs the table at image+0x800
 * -- `adr x2, #0x7FC; msr vbar_el1, x2` in its first three instructions -- but
 * the table it runs on later comes from a literal at 0x46C8 and is
 * 0xFFFF_FFFF_0000_4800.  And it runs on SP_ELx, not SP_EL0, so a current-EL
 * exception takes the slot at +0x200 rather than the first one.  A stub
 * anywhere else is never entered, which from outside looks exactly like "the
 * trap did not fire and the runtime halted anyway" -- so before reading
 * anything out of this, check that the guest is spinning at VECTOR+0x18 and
 * not in the runtime's own halt.
 */
#define OPEN_SECURE_ROM_TRAP_VECTOR 0xA00ULL
#endif

/*
 * One word to rewrite in the decrypted runtime image: its offset, the word that
 * must already be there, and the word to leave there.  A table of these is
 * applied all or nothing.
 */
typedef struct {
    sep_u32 offset;     /* into the decrypted image, which is what the window maps */
    sep_u32 was;        /* what must already be there, or this is not that build */
    sep_u32 word;       /* the instruction to leave there */
} boot_runtime_patch_t;

/*
 * The SEP console, which the firmware builds and then never feeds.
 *
 * SEPOS already has a working path into the AP shared buffer's `CONS` region:
 * the boot-time region parser recognises CONS/CORE/PNIC/TRAC, and the CONS arm
 * runs unconditionally for any CONS region of at least 0x101 bytes -- it
 * stores the base at image+0x205D8, sets the enable byte at image+0x205E8
 * (which has exactly one writer and no condition on it) and puts a 2 in
 * CONS[0].  The emitter at image+0x5604 appends a NUL-terminated string at
 * CONS[1..] and rings CONS[0].  **Its only caller is the panic path.**
 *
 * Everything userspace prints goes instead to the debug object -- type 9,
 * operation 0 -- whose invoke slot (image+0x14318+0x28) is image+0xFB90, and
 * in the release kernel that function reads no character at all: it computes
 * a result code out of the capability's rights bit 27 and returns.  So the
 * channel is built, enabled and wired, and the only thing missing is that the
 * character is dropped.
 *
 * These rows put it back.  The op-0 arm's last instruction is a `B` to the
 * shared result-code tail at image+0xFC3C; it is redirected into 56 bytes of
 * zeroes at image+0x46E8 (the tail of a literal pool, with no xref landing
 * anywhere in 0x46E8..0x47FF, and 0x4800 is VBAR so the page is executable),
 * which reads the character and appends it to CONS before branching to the
 * tail it replaced.  The character is the low byte of the saved user X2:
 * the EL0 vector stores X2/X3 at frame+0x10 and the SVC arm clobbers only the
 * register, not the saved copy, and image+0x20FC8 holds the frame pointer.
 * 0x20FC8 and 0x205D8 are in one 4 KB page, so one ADRP reaches both.
 *
 * It lands at **shared buffer + 0x14001** onward, NUL-terminated, in an 8 KB
 * ring -- readable with a plain `pmemsave`, with no AP cooperation and no
 * debugger.  Only X10..X14 are touched, and the dispatcher reloads all user
 * state from the frame afterwards, so userspace sees byte-for-byte what it
 * saw before.  Keyed on the op in X1 rather than on the result code, so a
 * capability without rights bit 27 cannot silently hide the log.
 *
 * Every offset here belongs to **AppleSEPOS-2437.0.30** (21A329).  The `was`
 * column is what makes that safe: on any other build the hook word is not
 * `B image+0xFC3C` and the whole table is declined rather than writing
 * fourteen words of someone else's code into someone else's image.
 */
#define BOOT_CONS_HOOK_AT   0x0000FBCCu
#define BOOT_CONS_HOOK_WAS  0x1400001Cu     /* B loc_FC3C */
#define BOOT_CONS_CAVE      0x000046E8u

static const boot_runtime_patch_t boot_runtime_patches[] = {
    { 0, 0, 0 },                  /* disarmed -- see the note below */
#if 0
    /*
     * DISARMED 2026-09-22, and what is known about why.
     *
     * Armed, the SEP dies in its own microkernel before a single thread
     * exists: `SEP Panic: :SEPOS/panic.c:345`, SEP state 7, thread table
     * "Unavailable".  Disarmed, the same boot goes back to where it
     * otherwise stops, `SEPD/AKF`.  So this table is the cause, not the boot.
     *
     * Two boots also settle *which half*: the guard below only applies the
     * table when every `was` already matches, so the fact that the machine's
     * behaviour changed at all proves the read through BOOT_RUNTIME_WINDOW
     * works, that the window really does map flat image offsets, and that
     * image+0xFBCC really is `B loc_FC3C` in this build.  The delivery
     * mechanism is sound; the fourteen words are what is wrong.
     *
     * Not yet established, and worth one look each before re-arming:
     *
     *   - the frame pointer.  `LDR X11,[X10,#0xFC8]` is not guarded the way
     *     the CONS base is, so a putchar taken before that global is set
     *     stores through a null pointer at +0x10.
     *   - the instruction cache.  This table had never been armed before, so
     *     `patch_runtime_image` has never been exercised at all; it cleans
     *     D-cache and does not call `sep_icache_invalidate_all`, which for
     *     fourteen words of new code in a page the core is about to execute
     *     is a gap whatever else is true.
     *
     * A SEP-only boot, without the AP chain, reproduces this in under a
     * minute and is the instrument for it rather than a full restore.
     */
    /* the hook: B loc_FC3C -> B cave */
    { BOOT_CONS_HOOK_AT,   BOOT_CONS_HOOK_WAS, 0x17FFD2C7u },
    /* the cave, which must be the zeroes it is in the shipped image */
    { BOOT_CONS_CAVE + 0x00, 0, 0xB50001A1u },  /* CBNZ X1, out        (op 0 only) */
    { BOOT_CONS_CAVE + 0x04, 0, 0x900000EAu },  /* ADRP X10, #0x20000              */
    { BOOT_CONS_CAVE + 0x08, 0, 0xF947E54Bu },  /* LDR  X11, [X10,#0xFC8] frame    */
    { BOOT_CONS_CAVE + 0x0C, 0, 0xF942ED4Cu },  /* LDR  X12, [X10,#0x5D8] CONS     */
    { BOOT_CONS_CAVE + 0x10, 0, 0xB400012Cu },  /* CBZ  X12, out       (no CONS)   */
    { BOOT_CONS_CAVE + 0x14, 0, 0xB945F14Du },  /* LDR  W13, [X10,#0x5F0] cursor   */
    { BOOT_CONS_CAVE + 0x18, 0, 0x120031ADu },  /* AND  W13, W13, #0x1FFF          */
    { BOOT_CONS_CAVE + 0x1C, 0, 0x3940416Eu },  /* LDRB W14, [X11,#0x10]  the char */
    { BOOT_CONS_CAVE + 0x20, 0, 0x8B2D418Cu },  /* ADD  X12, X12, W13,UXTW         */
    { BOOT_CONS_CAVE + 0x24, 0, 0x3900058Eu },  /* STRB W14, [X12,#1]              */
    { BOOT_CONS_CAVE + 0x28, 0, 0x3900099Fu },  /* STRB WZR, [X12,#2]   keep NUL   */
    { BOOT_CONS_CAVE + 0x2C, 0, 0x110005ADu },  /* ADD  W13, W13, #1               */
    { BOOT_CONS_CAVE + 0x30, 0, 0xB905F14Du },  /* STR  W13, [X10,#0x5F0]          */
    { BOOT_CONS_CAVE + 0x34, 0, 0x14002D48u },  /* B    loc_FC3C        (out)      */
#endif
};

/*
 * All of it or none of it.
 *
 * A half-applied table is worse than none: the hook without the cave runs the
 * image into zeroes, and the cave without the hook is fourteen words written
 * into a build that may be using them.  So every row is checked first, and one
 * mismatch declines the lot.
 */
static void patch_runtime_image(void)
{
    const sep_size_t count = sizeof(boot_runtime_patches) /
                             sizeof(boot_runtime_patches[0]);
    sep_size_t index;

    for (index = 0; index < count; ++index) {
        const sep_u32 *at;

        if (boot_runtime_patches[index].offset == 0) {
            continue;
        }
        at = (const sep_u32 *)(uintptr_t)(boot_runtime_patches[index].offset
                                          | BOOT_RUNTIME_WINDOW);
        if (*at != boot_runtime_patches[index].was) {
            return;             /* not the build these offsets describe */
        }
    }

    for (index = 0; index < count; ++index) {
        sep_u32 *at;

        if (boot_runtime_patches[index].offset == 0) {
            continue;
        }
        at = (sep_u32 *)(uintptr_t)(boot_runtime_patches[index].offset
                                    | BOOT_RUNTIME_WINDOW);
        *at = boot_runtime_patches[index].word;
        sep_dcache_clean_invalidate_range(at, sizeof(*at));
    }
}


static void write_runtime_tables(
    sep_u64 runtime_destination,
    sep_size_t handoff_offset
) {
    /*
     * How far to map, which is region one and not the handoff's
     * `runtime_region_length`: that field is a sizing value for the runtime
     * and says nothing about the region.  Mapped from the field when it read
     * 0x18000, the table stopped before the stacks and the first push took a
     * level three translation fault, ESR 0x9600_0047 with FAR at the stack
     * pointer.  Region one is the whole runtime aperture, the same one
     * `sep_runtime_configure_mapping_for_mode` maps for mode four.
     */
    const sep_size_t runtime_region_length =
        sep_runtime_region_length_checked(1);
    /*
     * Written through this ROM's window and named to the runtime by their
     * machine addresses: the tables it will load into TTBR0 and TTBR1 have to
     * be addresses its own MMU can use, and it has no window of ours.
     */
    sep_u64 *const low =
        (sep_u64 *)(uintptr_t)(BOOT_TABLE_TTBR0_OFFSET | BOOT_RUNTIME_WINDOW);
    sep_u64 *const high =
        (sep_u64 *)(uintptr_t)(BOOT_TABLE_TTBR1_OFFSET | BOOT_RUNTIME_WINDOW);
    sep_u64 *const handoff =
        (sep_u64 *)(uintptr_t)(handoff_offset | BOOT_RUNTIME_WINDOW);
    const sep_u64 block = 1ULL << BOOT_TABLE_BLOCK_SHIFT;
    sep_size_t index;

    /*
     * Both halves say the same thing, and neither of them is the identity.
     *
     * The runtime addresses its own image low as well as high: its per-core
     * stack is `(core << 15) - 0x4000` -- 0x2C000 for core six, which is
     * inside the image's own hole -- and the per-core structures it keeps are
     * at 0x20FC8, and both are computed, not PC-relative.  An identity low
     * half was tried and it sent those to real low memory: the stack pointer
     * moved, the bytes went somewhere else, and the runtime ended re-entering
     * its own synchronous vector at 0xFFFF_FFFF_0000_4A00 for ever.
     *
     * So: offset -> runtime_destination + offset, in both, for as far as the
     * region goes.
     */
    /*
     * Two of them, because the halves say different things about the same
     * memory: the runtime **writes itself through low addresses and executes
     * itself through high ones**.  Its platform setup stores to 0x60, 0x80C, 0xA00,
     * 0x1000, 0x4100 and 0x4110 -- absolute, low -- and 0x4110 is in the same
     * sixteen kilobyte page as the vector table at 0x4800 that it will be
     * executing out of.  One page cannot be writable and executable at once
     * once the runtime sets SCTLR.WXN, and it does; two mappings of it can.
     */
    sep_u64 *const low_pages =
        (sep_u64 *)(uintptr_t)(BOOT_TABLE_L3_LOW_OFFSET | BOOT_RUNTIME_WINDOW);
    sep_u64 *const high_pages =
        (sep_u64 *)(uintptr_t)(BOOT_TABLE_L3_HIGH_OFFSET | BOOT_RUNTIME_WINDOW);

    sep_memzero(low, BOOT_TABLE_SIZE);
    sep_memzero(high, BOOT_TABLE_SIZE);
    sep_memzero(low_pages, BOOT_TABLE_SIZE);
    sep_memzero(high_pages, BOOT_TABLE_SIZE);

    for (index = 0; index < BOOT_TABLE_L3_ENTRIES; ++index) {
        const sep_u64 address =
            runtime_destination + ((sep_u64)index << BOOT_TABLE_PAGE_SHIFT);
        /* The hole in the image: the block, the per-core state, the stacks. */
        const sep_bool data = index >= BOOT_TABLE_DATA_FIRST &&
                              index < BOOT_TABLE_DATA_LIMIT;

        if (((sep_u64)index << BOOT_TABLE_PAGE_SHIFT) >= runtime_region_length) {
            break;
        }
        low_pages[index] = address | BOOT_TABLE_PAGE_FLAGS
                           | BOOT_TABLE_NEVER_EXECUTE;
        high_pages[index] = address | BOOT_TABLE_PAGE_FLAGS
                            | (data ? BOOT_TABLE_NEVER_EXECUTE
                                    : BOOT_TABLE_READ_ONLY);
    }

    /* The first thirty-two megabytes of each half come from its own table. */
    low[0] = (runtime_destination + BOOT_TABLE_L3_LOW_OFFSET)
             | BOOT_TABLE_NEXT_LEVEL;
    high[0] = (runtime_destination + BOOT_TABLE_L3_HIGH_OFFSET)
              | BOOT_TABLE_NEXT_LEVEL;

    /*
     * A window on the platform registers, high, because once the runtime's
     * early setup sets TCR.EPD0 nothing low resolves at all.
     *
     * The runtime reaches them through a base it loads out of the block:
     * its platform setup does `ldr x8, [block + 0x560]` and then stores at +0x60,
     * +0x80C, +0xA00..+0xA0C, +0x1000..+0x1014, +0x4100 and +0x4110.  With the
     * slot left zero those go to low addresses and die on EPD0 -- measured,
     * ESR 0x9600_0044 with FAR 0x1000, which is what a disabled TTBR0 walk
     * reports.  0x2_5C20_0000 is the block the runtime reads at its very first
     * instruction, so that is what it is pointed at, aligned down to the
     * thirty-two megabytes a level two entry covers.
     */
    high[BOOT_TABLE_PLATFORM_SLOT] = BOOT_PLATFORM_PHYSICAL
                                     | BOOT_TABLE_BLOCK_FLAGS
                                     | BOOT_TABLE_NEVER_EXECUTE
                                     | (3ULL << 2);   /* MAIR index three */
    handoff[0x560 / 8] = BOOT_PLATFORM_VIRTUAL;


    /*
     * And the power object's state, which has to be one.
     *
     * The runtime's power-state check -- reached right after its platform
     * setup -- reads block+0x5C0 and halts at `obj_sep_power.c:122` unless it
     * is 1.  The suspend path writes it, so on a cold boot there is nobody
     * to write it but this side; the image ships that word inside its own hole
     * and this ROM zeroes the hole.  The magic beside it at image+0x14800 is
     * already 0xC3C3C3C3C3C3C3C3 in the image and is accepted as it stands.
     */
#if OPEN_SECURE_ROM_FORCE_SUSPEND_STATE
    handoff[0x5C0 / 8] = 1;
#endif

    /*
     * And a second peripheral pointer beside it, at block+0x5C8.  Measured:
     * with it zero, SEPOS reaches `0xFFFF_FFFF_0000_6338` and stores through
     * it -- `STR wzr, [x8]`, then 3 at +0x4 and zero at +0xC -- which with
     * TCR.EPD0 already set is a level-zero translation fault on address zero
     * (ESR 0x96000044, FAR 0).  It is read at two sites and written at none,
     * so it is a handoff field like +0x560 and not something SEPOS fills.
     *
     * Confirmed on the machine: SEPOS's own dispatcher stores ESR at frame
     * +104 and FAR at +105, and they read 0x96000044 and 0x4 -- a write of 3
     * to offset four of a null pointer, which is `MOV w9,#3; STR w9,[x8,#4]`
     * at 0x6340 with x8 loaded from this field.  Reading them out of the guest
     * is the only way to see this: the runtime's system registers do not come
     * back through the debug stub, and a stub planted in its vector reports
     * whatever the last exception left rather than this one.
     *
     * What it points at is the SEP's power controller, and this ROM does not
     * model one: the pointer goes to an otherwise unused page of the same
     * peripheral block -- the 32 MiB block at high[120] covers it -- so the
     * three stores land somewhere backed.  Nothing reads them back yet, so
     * that is enough to get past the fault; the day SEPOS wants a power state
     * out of it, this is where to look.
     */
#if OPEN_SECURE_ROM_FORCE_SUSPEND_STATE
    handoff[0x5C8 / 8] = BOOT_PLATFORM_VIRTUAL + 0xF0000;
#endif
    /*
     * And the magic beside it.
     *
     * The power-state check takes one path and it is the one a suspend leaves behind: the
     * word at block+0x5C0 has to be 1 *and* the magic at image+0x14800 has to
     * be 0x5A5A5A5A5A5A5A5A.  The image ships 0xC3C3C3C3C3C3C3C3 there, which
     * the same function explicitly recognises and then halts on --
     * `obj_sep_power.c:89`, as against `:122` for a zero state.  So the ROM
     * hands the runtime the state its own suspend path would have written.
     */
#if OPEN_SECURE_ROM_FORCE_SUSPEND_STATE
    *(sep_u64 *)(uintptr_t)(0x14800ULL | BOOT_RUNTIME_WINDOW) =
        0x5A5A5A5A5A5A5A5AULL;
#endif
    sep_dcache_clean_invalidate_range(
        (const void *)(uintptr_t)(0x14800ULL | BOOT_RUNTIME_WINDOW),
        16
    );

    /*
     * And the top of the high window, where the stack is.
     *
     * The runtime puts its stack at `(core << 15) - 0x4000`, and on a part
     * with one core that is -0x4000: the last sixteen kilobytes of TTBR1's
     * four gigabytes, 0xFFFF_FFFF_FFFF_C000.  Measured with the core numbered
     * zero -- ESR 0x9600_0046, a level two translation fault on a store, FAR
     * exactly 0xFFFF_FFFF_FFFF_BFE0.  Nothing else is up there, so the last
     * block is given the region's own tail, which the image does not reach.
     */
    high[BOOT_TABLE_HIGH_ENTRIES - 1] =
        runtime_destination | BOOT_TABLE_BLOCK_FLAGS
        | BOOT_TABLE_NEVER_EXECUTE;

    /*
     * And the region again at its machine addresses, as one block, so the
     * instruction after the one that enables the MMU can still be fetched.
     * Read-only, for the same reason everything executable here is.
     */
    for (index = 0; index < BOOT_TABLE_HIGH_ENTRIES; ++index) {
        const sep_u64 address = runtime_destination + (sep_u64)index * block;
        const sep_size_t slot = (sep_size_t)(address >> BOOT_TABLE_BLOCK_SHIFT);

        if ((sep_u64)index * block >= runtime_region_length + block) {
            break;
        }
        if (slot != 0 && slot < BOOT_TABLE_ENTRIES) {
            low[slot] = address | BOOT_TABLE_BLOCK_FLAGS
                        | BOOT_TABLE_READ_ONLY;
        }
    }


    sep_dcache_clean_invalidate_range(low, BOOT_TABLE_SIZE);
    sep_dcache_clean_invalidate_range(high, BOOT_TABLE_SIZE);
    sep_dcache_clean_invalidate_range(low_pages, BOOT_TABLE_SIZE);
    sep_dcache_clean_invalidate_range(high_pages, BOOT_TABLE_SIZE);

#if OPEN_SECURE_ROM_TRAP_RUNTIME_ENTRY
    /*
     * What the runtime is actually handed.
     *
     * Its first argument selects which of its two entries runs, and reasoning
     * about that statically went wrong twice.  So the entry itself
     * is replaced with three instructions that park x0 and x1 where the debug
     * stub can read them and stop.  The runtime does not boot with this on --
     * that is the point; read x5 and x6 and turn it back off.
     */
    {
        /*
         * At the runtime's own fork, not at its entry: image+0x40F8 is the
         * `cbz x19, resume` that chooses between the cold stub at 0x4660 and
         * the resume stub at 0x4694, and x19 is what everything upstream is
         * arguing about.  x20 is the second argument as the runtime sees it,
         * after its first instruction (`adr x1, #0`) has already overwritten
         * whatever was handed in x1.
         */
        /*
         * At the runtime's call to its block builder, to settle what base the
         * `+0x1068` and `+0x1070` fields are relative to.  The cold stub copies
         * sixteen kilobytes to image+0x1C000 and appears to pass that as the
         * fourth argument, which would make the fields image+0x1D068 rather
         * than image+0x1068 -- a difference that reading them as image-header
         * offsets hides completely.  x3 is that argument and x2 the handoff
         * pointer beside it.
         */
        sep_u32 *const entry =
            (sep_u32 *)(uintptr_t)(0x413CULL | BOOT_RUNTIME_WINDOW);

        entry[0] = 0xAA0303E5u;     /* mov x5, x3 */
        entry[1] = 0xAA0203E6u;     /* mov x6, x2 */
        entry[2] = 0x14000000u;     /* b .        */
        sep_dcache_clean_invalidate_range(entry, 16);
    }
#endif

#if OPEN_SECURE_ROM_TRAP_RUNTIME_FAULT
    /*
     * Make the runtime's synchronous vector say what went wrong.
     *
     * It is stuck re-entering that vector and this side cannot read the
     * runtime's ESR: under HVF the system registers of a guest vCPU do not
     * come back through the debug stub.  So the vector is replaced with four
     * instructions that put the answer where the general registers are, which
     * do come back:
     *
     *     mrs x0, esr_el1 ; mrs x1, far_el1 ; mrs x2, elr_el1 ; b .
     *
     * A debugging aid, and only that -- turn it off to boot the image as it
     * was shipped.
     */
    {
        sep_u32 *const vector =
            (sep_u32 *)(uintptr_t)(OPEN_SECURE_ROM_TRAP_VECTOR
                                   | BOOT_RUNTIME_WINDOW);

        /*
         * Two instructions that cannot fault or trap, ahead of the reads.
         * A vector whose *entry* keeps re-faulting parks the core on its first
         * word forever, which from outside is indistinguishable from a core
         * that stopped before ever reaching it -- and both look like "PC is
         * the vector address".  If x5 comes back 0x1234 the core is running
         * and the reads below are what to trust; if it does not, nothing here
         * ran and the registers belong to whatever faulted.
         */
        vector[0] = 0xD2824685u;    /* movz x5, #0x1234  */
        vector[1] = 0xD28ACF06u;    /* movz x6, #0x5678  */
        vector[2] = 0xD5385200u;    /* mrs x0, esr_el1  */
        vector[3] = 0xD5386001u;    /* mrs x1, far_el1  */
        vector[4] = 0xD5384022u;    /* mrs x2, elr_el1  */
        vector[5] = 0xD5382043u;    /* mrs x3, tcr_el1   */
        vector[6] = 0x14000000u;    /* b .               */
        sep_dcache_clean_invalidate_range(vector, 32);
    }
#endif

    handoff[0x68 / 8] = runtime_destination + BOOT_TABLE_TTBR0_OFFSET;
    handoff[0x70 / 8] = runtime_destination + BOOT_TABLE_TTBR1_OFFSET;
    sep_dcache_clean_invalidate_range(handoff, 0x80);
    patch_runtime_image();
}

sep_u64 sep_boot_build_runtime_handoff(
    const sep_shared_image_context_t *image,
    sep_size_t payload_length,
    sep_size_t manifest_length,
    sep_u32 runtime_mode
) {
    sep_boot_runtime_handoff_t handoff;
    sep_size_t aligned_offset;
    const sep_u64 handoff_address = build_runtime_handoff(
        &handoff,
        &aligned_offset,
        image,
        payload_length,
        manifest_length,
        runtime_mode
    );
    /*
     * Through this ROM's own window over the runtime region, not through the
     * address the runtime is handed.
     *
     * `sep_runtime_configure_mapping_for_mode` maps the region at virtual
     * 0x08_0000_0000 for mode four, so 0x08_0000_0000 + offset is where this
     * side writes and `runtime_destination + offset` is what the far side will
     * call it.  The two are the same memory under different names, and mixing
     * them up costs a data abort: writing straight to `handoff_address` was
     * tried and the ROM took one, ESR 0x9600_0046 -- a write, translation
     * fault at level two -- in `sep_memmove`.
     */
    /*
     * At `aligned_offset`, which is the address the runtime is handed, and not
     * at BOOT_HANDOFF_OFFSET: the runtime reads its magic at the address it is
     * given and answers a mismatch with `wfe` in a loop, and image+0x20000 is
     * where the t8110 cold path writes its copy, over anything put there.
     */
    sep_memmove(
        (void *)(uintptr_t)(aligned_offset | BOOT_RUNTIME_WINDOW),
        &handoff,
        sizeof(handoff)
    );

    const sep_boot_platform_t *const platform = sep_boot_platform();
    /*
     * And then one field of it may say something else: a platform whose
     * runtime reads runtime_destination back as a number rather than as the
     * address it was entered at.  Moving the image to satisfy that number
     * satisfies neither use, so only the field changes.
     */
    if (platform->reported_destination != 0) {
        *(sep_u64 *)(uintptr_t)((aligned_offset + 0x18) | BOOT_RUNTIME_WINDOW) =
            platform->reported_destination;
    }
    sep_dcache_clean_invalidate_range(
        (const void *)(uintptr_t)(aligned_offset | BOOT_RUNTIME_WINDOW),
        64
    );
    if (platform->rom_builds_translation_tables) {
        write_runtime_tables(
            handoff.runtime_destination,
            BOOT_HANDOFF_OFFSET
        );
    }
    return handoff_address;
}
