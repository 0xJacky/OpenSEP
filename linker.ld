ENTRY(sep_reset_entry)

ROM_BASE = 0x02000000;
ROM_LIMIT = 0x02029000;
RAM_BASE = 0x04020000;
RAM_LIMIT = 0x04024000;
EL0_STACK_BOTTOM = 0x04028000;
EL0_STACK_TOP = 0x04030000;
EL1_STACK_BOTTOM = 0x04034000;
EL1_STACK_TOP = 0x04038000;
TRANSLATION_TABLE_BASE = 0x04040000;
TRANSLATION_TABLE_LIMIT = 0x04050000;

SECTIONS
{
    . = ROM_BASE;
    .text : ALIGN(16) {
        KEEP(*(.text.start))
        . = ROM_BASE + 0x4000;
        __exception_vector_start = .;
        KEEP(*(.text.open_secure_rom_exception_vectors))
        __exception_vector_end = .;
        *(.text .text.*)
    }
    .rodata : ALIGN(16) {
        *(.rodata .rodata.*)
    }
    . = ALIGN(16);
    __data_load_start = .;

    .data RAM_BASE + 8 : AT(__data_load_start) {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    .platform_provisioning_cache 0x04020600 (NOLOAD) : {
        KEEP(*(.platform_provisioning_cache))
    }

    .platform_configuration_initialized 0x04020680 (NOLOAD) : {
        KEEP(*(.platform_configuration_initialized))
    }

    .runtime_authentication_state 0x04020681 (NOLOAD) : {
        KEEP(*(.runtime_authentication_state))
    }

    .platform_configuration 0x04020700 (NOLOAD) : {
        KEEP(*(.platform_configuration))
    }

    .runtime_mapping_state 0x04020880 (NOLOAD) : {
        KEEP(*(.runtime_mapping_state))
    }

    .panic_recursion_state 0x04020886 (NOLOAD) : {
        KEEP(*(.panic_recursion_state))
    }

    .platform_provisioning_state 0x040208f0 (NOLOAD) : {
        KEEP(*(.platform_provisioning_state))
    }

    .runtime_handoff_metadata 0x04020a74 (NOLOAD) : {
        KEEP(*(.runtime_handoff_metadata))
    }

    .assertion_state 0x04020af8 (NOLOAD) : {
        KEEP(*(.assertion_state))
    }

    .runtime_regions 0x04020f50 (NOLOAD) : {
        KEEP(*(.runtime_regions))
    }

    __runtime_state_end = .;

    __rom_end = __data_load_start + SIZEOF(.data);
    __el0_stack_bottom = EL0_STACK_BOTTOM;
    __el0_stack_top = EL0_STACK_TOP;
    __el1_stack_bottom = EL1_STACK_BOTTOM;
    __el1_stack_top = EL1_STACK_TOP;
    __translation_table_base = TRANSLATION_TABLE_BASE;
    __translation_table_limit = TRANSLATION_TABLE_LIMIT;
    __stack_bottom = EL0_STACK_BOTTOM;
    __stack_top = EL0_STACK_TOP;

    .debug_abbrev 0 : { *(.debug_abbrev) }
    .debug_aranges 0 : { *(.debug_aranges) }
    .debug_addr 0 : { *(.debug_addr) }
    .debug_frame 0 : { *(.debug_frame) }
    .debug_info 0 : { *(.debug_info .debug_info.*) }
    .debug_line 0 : { *(.debug_line .debug_line.*) }
    .debug_line_str 0 : { *(.debug_line_str) }
    .debug_loclists 0 : { *(.debug_loclists) }
    .debug_rnglists 0 : { *(.debug_rnglists) }
    .debug_str 0 : { *(.debug_str .debug_str.*) }
    .debug_str_offsets 0 : { *(.debug_str_offsets) }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note*)
        *(.llvm_addrsig)
    }
}

ASSERT(__rom_end <= ROM_LIMIT, "OpenSEP exceeds the AVPSEPBooter ROM window")
ASSERT(__data_start == RAM_BASE + 8, "OpenSEP data overlaps the official main seed word")
ASSERT(__bss_start >= RAM_BASE + 0x10, "OpenSEP BSS overlaps initialized data")
ASSERT(__bss_end <= 0x04020600, "OpenSEP BSS exceeds the recovered startup state window")
ASSERT(__bss_end <= RAM_LIMIT, "OpenSEP state exceeds the recovered RAM window")
ASSERT(__runtime_state_end <= RAM_LIMIT, "OpenSEP fixed runtime state exceeds the recovered RAM window")
ASSERT(sep_vector_table == ROM_BASE + 0x800, "OpenSEP early vectors moved from the recovered address")
ASSERT(__exception_vector_start == ROM_BASE + 0x4000, "OpenSEP runtime vectors moved from the recovered address")
ASSERT((__exception_vector_start & 0x7ff) == 0, "OpenSEP runtime vectors are not VBAR aligned")
ASSERT(__el0_stack_bottom >= RAM_LIMIT, "OpenSEP EL0 stack overlaps runtime state")
ASSERT(__el0_stack_top <= __el1_stack_bottom, "OpenSEP stack banks overlap")
ASSERT(__el1_stack_top <= TRANSLATION_TABLE_BASE, "OpenSEP EL1 stack overlaps translation tables")
ASSERT(TRANSLATION_TABLE_LIMIT <= 0x04100000, "OpenSEP translation tables exceed bootstrap RAM")
