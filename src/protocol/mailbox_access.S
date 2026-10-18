.text
.p2align 2
.global sep_mailbox_load_pair
.type sep_mailbox_load_pair,@function
sep_mailbox_load_pair:
    ldp x0, x1, [x0]
    ret
.size sep_mailbox_load_pair, .-sep_mailbox_load_pair

.global sep_mailbox_store_pair
.type sep_mailbox_store_pair,@function
sep_mailbox_store_pair:
    stp x1, x2, [x0]
    ret
.size sep_mailbox_store_pair, .-sep_mailbox_store_pair
