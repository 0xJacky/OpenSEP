.text
.p2align 2
.global sep_read_cntpct_synchronized
.type sep_read_cntpct_synchronized,@function
sep_read_cntpct_synchronized:
    dsb sy
    isb
    mrs x0, cntpct_el0
    ret
.size sep_read_cntpct_synchronized, .-sep_read_cntpct_synchronized

.global sep_icache_invalidate_all
.type sep_icache_invalidate_all,@function
sep_icache_invalidate_all:
    ic iallu
    dsb sy
    isb
    ret
.size sep_icache_invalidate_all, .-sep_icache_invalidate_all

.global sep_icache_invalidate_by_va
.type sep_icache_invalidate_by_va,@function
sep_icache_invalidate_by_va:
    ic ivau, x0
    ret
.size sep_icache_invalidate_by_va, .-sep_icache_invalidate_by_va

.global sep_dcache_clean_by_va
.type sep_dcache_clean_by_va,@function
sep_dcache_clean_by_va:
    dc cvac, x0
    ret
.size sep_dcache_clean_by_va, .-sep_dcache_clean_by_va

.global sep_dcache_invalidate_by_va
.type sep_dcache_invalidate_by_va,@function
sep_dcache_invalidate_by_va:
    dc ivac, x0
    ret
.size sep_dcache_invalidate_by_va, .-sep_dcache_invalidate_by_va

.global sep_dcache_clean_invalidate_by_va
.type sep_dcache_clean_invalidate_by_va,@function
sep_dcache_clean_invalidate_by_va:
    dc civac, x0
    ret
.size sep_dcache_clean_invalidate_by_va, .-sep_dcache_clean_invalidate_by_va

.global open_secure_rom_tlbi_vaale1
.type open_secure_rom_tlbi_vaale1,@function
open_secure_rom_tlbi_vaale1:
    tlbi vaale1, x0
    ret
.size open_secure_rom_tlbi_vaale1, .-open_secure_rom_tlbi_vaale1

.global open_secure_rom_tlbi_vmalle1
.type open_secure_rom_tlbi_vmalle1,@function
open_secure_rom_tlbi_vmalle1:
    tlbi vmalle1
    ret
.size open_secure_rom_tlbi_vmalle1, .-open_secure_rom_tlbi_vmalle1
