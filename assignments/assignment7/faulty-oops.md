# Fauly analysis

Based on the oops message below we can say the following:

    1. Triggering event: null pointer dereferencing
    2. Module: faulty
    3. Memory abort information: `EC=0x25` (data abort) `FSC=0x05` (level 1 translation fault) - fault occurred because of a missing translation at the first level of the memory address translation tables.
    4. `Call trace` shows the sequence of functions leading up to the Oops. Basically Oops happened inside the `faulty_write` function of the `faulty` module. The subsequent calls to `vfs_write` and `ksys_write` are part of the normal file system and syscall handling.
    5. Code dump: The code dump shows the instructions that caused the Oops:

    Code: 91000000 95ff678c d2800001 d2800000 (b900003f)

    This instruction corresponds to a memory store operation (`str`), where the kernel is attempting to store a value at the address stored in `x0`, which is 0 (NULL).

    # echo "hello" > /dev/faulty
    [  502.081078] KERNEL ALERT: calling faulty module at faulty_write 53
    [  502.169966] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
    [  502.170718] Mem abort info:
    [  502.170872]   ESR = 0x96000045
    [  502.171171]   EC = 0x25: DABT (current EL), IL = 32 bits
    [  502.171383]   SET = 0, FnV = 0
    [  502.171518]   EA = 0, S1PTW = 0
    [  502.171658]   FSC = 0x05: level 1 translation fault
    [  502.171853] Data abort info:
    [  502.171983]   ISV = 0, ISS = 0x00000045
    [  502.172135]   CM = 0, WnR = 1
    [  502.172424] user pgtable: 4k pages, 39-bit VAs, pgdp=00000000425a3000
    [  502.172705] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
    [  502.174496] Internal error: Oops: 96000045 [#1] SMP
    [  502.175006] Modules linked in: hello(O) faulty(O) scull(O)
    [  502.202109] CPU: 0 PID: 163 Comm: sh Tainted: G           O      5.15.18 #2
    [  502.210685] Hardware name: linux,dummy-virt (DT)
    [  502.211268] pstate: 60000005 (nZCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
    [  502.211822] pc : faulty_write+0x2c/0xe40 [faulty]
    [  502.330525] lr : faulty_write+0x24/0xe40 [faulty]
    [  502.330696] sp : ffffffc00918bd70
    [  502.330839] x29: ffffffc00918bd70 x28: ffffff8002564c80 x27: 0000000000000000
    [  502.331079] x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
    [  502.331218] x23: 0000000020001000 x22: 0000000000000006 x21: 0000005592662500
    [  502.331362] x20: 0000005592662500 x19: ffffff80016b0e00 x18: 0000000000000030
    [  502.331605] x17: 0000000000000000 x16: 0000000000000000 x15: ffffffffffffffff
    [  502.331937] x14: 0000000000000000 x13: 3335206574697277 x12: ffffffc008dd09c8
    [  502.332234] x11: 0000000000000096 x10: 6d2079746c756166 x9 : 00000000ffffefff
    [  502.332426] x8 : ffffffc008e289c8 x7 : 0000000000017fe8 x6 : 0000000000000001
    [  502.398555] x5 : 0000000000000000 x4 : 0000000000000000 x3 : 0000000000000000
    [  502.464277] x2 : 0000000000000000 x1 : 0000000000000000 x0 : 0000000000000000
    [  502.464651] Call trace:
    [  502.464852]  faulty_write+0x2c/0xe40 [faulty]
    [  502.464994]  vfs_write+0xf8/0x280
    [  502.465377]  ksys_write+0x68/0xf0
    [  502.465458]  __arm64_sys_write+0x20/0x30
    [  502.465582]  invoke_syscall+0x7c/0x110
    [  502.465668]  el0_svc_common.constprop.0+0xc0/0xf0
    [  502.469914]  do_el0_svc+0x7c/0x90
    [  502.470012]  el0_svc+0x20/0x50
    [  502.470073]  el0t_64_sync_handler+0x44/0xf0
    [  502.470226]  el0t_64_sync+0x1a0/0x1a4
    [  502.470949] Code: 91000000 95ff678c d2800001 d2800000 (b900003f)
    [  502.471706] ---[ end trace 85486d2cc7b87e3d ]---
