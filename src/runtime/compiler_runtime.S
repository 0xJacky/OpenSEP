.text
.p2align 2

.global sep_chkstk_darwin
.type sep_chkstk_darwin,@function
sep_chkstk_darwin:
    bti c
    b sep_chkstk_darwin_probe_veneer
.size sep_chkstk_darwin, .-sep_chkstk_darwin

.global sep_chkstk_darwin_probe_veneer
.type sep_chkstk_darwin_probe_veneer,@function
sep_chkstk_darwin_probe_veneer:
    bti c
    mov x10, sp
    cmp x9, #1, lsl #12
    b.lo 2f
1:
    sub x10, x10, #1, lsl #12
    ldrb wzr, [x10]
    sub x9, x9, #1, lsl #12
    cmp x9, #1, lsl #12
    b.hi 1b
2:
    sub x10, x10, x9
    ldrb wzr, [x10]
    ret
.size sep_chkstk_darwin_probe_veneer, .-sep_chkstk_darwin_probe_veneer
