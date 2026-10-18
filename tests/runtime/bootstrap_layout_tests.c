#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "open_secure_rom/runtime/boot/bootstrap.h"

static void test_recovered_system_register_contract(void) {
    assert(SEP_BOOT_MAIR_EL1 == UINT64_C(0x444f00));
    assert(SEP_BOOT_TCR_EL1 == UINT64_C(0x34080a51c));
    assert(SEP_BOOT_SCTLR_EARLY_BITS == UINT64_C(0x1000));
    assert(SEP_BOOT_SCTLR_ENABLE_BITS == UINT64_C(0x0d));
}

static void test_translation_hierarchy(void) {
    assert(
        SEP_BOOT_TABLE_LIMIT - SEP_BOOT_ROOT_TABLE ==
        4 * SEP_BOOT_PAGE_SIZE
    );
    assert(
        SEP_BOOT_ROM_MAPPED_SIZE / SEP_BOOT_PAGE_SIZE == 20
    );
    assert(SEP_BOOT_ROOT_INDEX(SEP_BOOT_ROM_BASE) == 1);
    assert(SEP_BOOT_ROOT_INDEX(SEP_BOOT_RUNTIME_RAM_BASE) == 2);
    assert(SEP_BOOT_ROOT_INDEX(SEP_BOOT_MAILBOX_VA) == 2);
    assert(SEP_BOOT_ROOT_INDEX(SEP_BOOT_PLATFORM_MMIO) == 24);
    assert(SEP_BOOT_ROOT_INDEX(SEP_BOOT_CONFIGURATION_SINK_MMIO) == 24);
    assert(SEP_BOOT_ROOT_INDEX(SEP_BOOT_LOW_APERTURE_VA) == 16);
    assert(SEP_BOOT_ROOT_INDEX(SEP_BOOT_RUNTIME_WINDOW_VA) == 1024);

    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_RUNTIME_RAM_BASE) == 8);
    assert(SEP_BOOT_PAGE_INDEX(UINT64_C(0x04024000)) == 9);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_EL0_STACK_BOTTOM) == 10);
    assert(SEP_BOOT_PAGE_INDEX(UINT64_C(0x0402c000)) == 11);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_EL0_STACK_TOP) == 12);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_EL1_STACK_BOTTOM) == 13);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_EL1_STACK_TOP) == 14);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_RUNTIME_EXTENSION_VA) == 15);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_RUNTIME_TAIL_VA) == 19);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_TABLE_ALIAS_VA) == 21);
    assert(SEP_BOOT_PAGE_INDEX(SEP_BOOT_MAILBOX_VA) == 0x400);
}

static void test_descriptor_values(void) {
    assert(
        SEP_BOOT_PAGE_DESCRIPTOR(
            SEP_BOOT_ROM_BASE,
            SEP_BOOT_ROM_PAGE_FLAGS
        ) == UINT64_C(0x0004000002000687)
    );
    assert(
        SEP_BOOT_PAGE_DESCRIPTOR(
            SEP_BOOT_RUNTIME_RAM_BASE,
            SEP_BOOT_RAM_PAGE_FLAGS
        ) == UINT64_C(0x0064000004020607)
    );
    static const uint64_t expected_runtime_descriptors[] = {
        UINT64_C(0x0064000004020607),
        UINT64_C(0),
        UINT64_C(0x0064000004024607),
        UINT64_C(0x0064000004028607),
        UINT64_C(0),
        UINT64_C(0x006400000402c607),
        UINT64_C(0),
        UINT64_C(0x0064000004030607),
        UINT64_C(0x0064000004034607),
        UINT64_C(0x0064000004038607),
        UINT64_C(0),
        UINT64_C(0x006400000403c607),
        UINT64_C(0),
        UINT64_C(0x0064000004040607),
        UINT64_C(0x0064000004044607),
        UINT64_C(0x0064000004048607),
        UINT64_C(0x006400000404c607),
    };
    uint64_t runtime_descriptors[17] = {0};
    runtime_descriptors[0] = SEP_BOOT_PAGE_DESCRIPTOR(
        SEP_BOOT_RUNTIME_RAM_BASE,
        SEP_BOOT_RAM_PAGE_FLAGS
    );
    runtime_descriptors[2] = SEP_BOOT_PAGE_DESCRIPTOR(
        SEP_BOOT_EL0_STACK_PHYSICAL_BOTTOM,
        SEP_BOOT_RAM_PAGE_FLAGS
    );
    runtime_descriptors[3] = runtime_descriptors[2] + SEP_BOOT_PAGE_SIZE;
    runtime_descriptors[5] = SEP_BOOT_PAGE_DESCRIPTOR(
        SEP_BOOT_EL1_STACK_PHYSICAL_BOTTOM,
        SEP_BOOT_RAM_PAGE_FLAGS
    );
    for (size_t page = 0; page < 3; ++page) {
        runtime_descriptors[7 + page] = SEP_BOOT_PAGE_DESCRIPTOR(
            SEP_BOOT_RUNTIME_EXTENSION_PA + page * SEP_BOOT_PAGE_SIZE,
            SEP_BOOT_RAM_PAGE_FLAGS
        );
    }
    runtime_descriptors[11] = SEP_BOOT_PAGE_DESCRIPTOR(
        SEP_BOOT_RUNTIME_TAIL_PA,
        SEP_BOOT_RAM_PAGE_FLAGS
    );
    for (size_t page = 0; page < 4; ++page) {
        runtime_descriptors[13 + page] = SEP_BOOT_PAGE_DESCRIPTOR(
            SEP_BOOT_ROOT_TABLE + page * SEP_BOOT_PAGE_SIZE,
            SEP_BOOT_RAM_PAGE_FLAGS
        );
    }
    for (size_t index = 0; index < 17; ++index) {
        assert(runtime_descriptors[index] == expected_runtime_descriptors[index]);
    }
    assert(
        SEP_BOOT_PAGE_DESCRIPTOR(
            SEP_BOOT_MAILBOX_PA,
            SEP_BOOT_DEVICE_PAGE_FLAGS
        ) == UINT64_C(0x0064000030250603)
    );
    assert(
        SEP_BOOT_DEVICE_BLOCK_DESCRIPTOR == UINT64_C(0x0064000000000601)
    );
    assert(
        SEP_BOOT_PAGE_DESCRIPTOR(
            SEP_BOOT_LOW_APERTURE_PA,
            SEP_BOOT_LOW_APERTURE_BLOCK_FLAGS
        ) == UINT64_C(0x0064000020000601)
    );
    assert(
        SEP_BOOT_PAGE_DESCRIPTOR(
            SEP_BOOT_RUNTIME_WINDOW_PA,
            SEP_BOOT_RUNTIME_WINDOW_BLOCK_FLAGS
        ) == UINT64_C(0x0004000006000605)
    );
    assert(
        (uint64_t)SEP_BOOT_RUNTIME_WINDOW_PA +
            (uint64_t)SEP_BOOT_RUNTIME_WINDOW_BLOCK_COUNT *
                SEP_BOOT_DEVICE_BLOCK_SIZE ==
        SEP_BOOT_RUNTIME_WINDOW_EXTENSION_PA
    );
    assert(
        SEP_BOOT_DEVICE_BLOCK_TRANSLATE(SEP_BOOT_PLATFORM_MMIO) ==
        UINT64_C(0x00400000)
    );
    assert(
        SEP_BOOT_DEVICE_BLOCK_TRANSLATE(
            SEP_BOOT_CONFIGURATION_SINK_MMIO
        ) == UINT64_C(0x00600000)
    );
}

static void test_guarded_stack_layout(void) {
    assert(SEP_BOOT_RUNTIME_RAM_LIMIT < SEP_BOOT_EL0_STACK_BOTTOM);
    assert(SEP_BOOT_EL0_STACK_TOP < SEP_BOOT_EL1_STACK_BOTTOM);
    assert(SEP_BOOT_EL1_STACK_TOP < SEP_BOOT_ROOT_TABLE);
    assert(
        SEP_BOOT_EL0_STACK_TOP - SEP_BOOT_EL0_STACK_BOTTOM ==
        2 * SEP_BOOT_PAGE_SIZE
    );
    assert(
        SEP_BOOT_EL1_STACK_TOP - SEP_BOOT_EL1_STACK_BOTTOM ==
        SEP_BOOT_PAGE_SIZE
    );
    assert(SEP_BOOT_EL0_STACK_PHYSICAL_BOTTOM == UINT64_C(0x04024000));
    assert(SEP_BOOT_EL1_STACK_PHYSICAL_BOTTOM == UINT64_C(0x0402c000));
    assert(SEP_BOOT_RUNTIME_CLEAR_BASE == UINT64_C(0x04020600));
    assert(SEP_BOOT_RUNTIME_CLEAR_LIMIT == UINT64_C(0x04021080));
    assert((SEP_BOOT_RUNTIME_CLEAR_LIMIT - SEP_BOOT_RUNTIME_CLEAR_BASE) % 16 == 0);
}

int main(void) {
    test_recovered_system_register_contract();
    test_translation_hierarchy();
    test_descriptor_values();
    test_guarded_stack_layout();
    puts("bootstrap layout tests passed");
    return 0;
}
