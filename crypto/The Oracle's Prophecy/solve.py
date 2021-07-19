# Second half of the flag
# PCBC Adjacent Swap Attack + Padding Oracle Attack

from pwn import *;

# conn = remote('localhost',31337);
conn = remote("oracleprophecy.litctf.live",1337);

def ask(conn,s):
	conn.recvline();
	conn.recvline();
	conn.recvline();
	conn.sendline("V");
	conn.sendline(s);
	res = conn.recvline();
	#print(res.decode("utf-8").rstrip());
	return res.decode("utf-8").rstrip() == "Please input the cryptic prophecy: The prophecy is fulfilled!";

def attempt(conn,offset):
	conn.recvline();
	conn.recvline();
	conn.recvline();
	conn.sendline("E");
	conn.recv();
	current = ''.join(random.choice("0123456789abcdef") for _ in range(13 + offset));
	conn.sendline(current);
	h = conn.recvline().decode("utf-8").split(": ")[1].rstrip();
	swaps = h[:32] + h[12 * 32:13 * 32] + h[2 * 32:12 * 32] + h[32:2 * 32] + h[13 * 32:];
	# print(swaps);
	# print(current);
	res = ask(conn,swaps);

	if(res):
		# Yay P11[1] = IV[1] xor 16 xor P12[1]
		iv1 = int(h[:2],16);
		P11 = ord(current[3 + offset]);
		# print(current[3] + " " + str(P11))
		C10 = int(h[11 * 32:11 * 32 + 2],16);
		P10 = iv1 ^ (16 - offset) ^ P11 ^ C10;
		# print(iv1);
		# print(P10);
		return chr(P10);
	return False;

conn.recvline();
ans = "";
counter = 0
for i in range(12):
	while True:
		res = attempt(conn,i);
		counter += 1;
		if(res):
			#print("YAYYYYYYYYYYYYYYYYYYYYYYYY")
			print(res);
			counter = 0;
			ans += res;
			break;

print(ans);
