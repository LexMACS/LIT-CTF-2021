from pwn import *

def bytes2Int(b):
	return int(hex(b)[2:],16);

b1 = open("yougotrickrolled1.bmp","rb");
b2 = open("yougotrickrolled2.bmp","rb");
b3 = open("yougotrickrolled3.bmp","rb")

b1.seek(4800)
b2.seek(4800)
b3.seek(4800)
bin_str = ""
for j in range(50 * 8):
	c1 = str(int.from_bytes(b1.read(1),"big") & 1)
	c2 = str(int.from_bytes(b2.read(1),"big") & 1)
	c3 = str(int.from_bytes(b3.read(1),"big") & 1)
	if(c1 == c2):
		bin_str += c3;
	elif(c1 == c3):
		bin_str += c2;
	else:
		bin_str += c1;

char_str = unbits(bin_str,endian = 'little')
print("".join(map(lambda c: chr(c ^ 104), char_str)));