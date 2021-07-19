# First half of the flag, needs string from second half first tho

from pwn import *;

conn = remote('oracleprophecy.litctf.live',1337);

def ask(conn,s):
	conn.recvline();
	conn.recvline();
	conn.recvline();
	conn.sendline("V");
	conn.sendline(s);
	res = conn.recvline();
	# print(res.decode("utf-8").rstrip());
	return res.decode("utf-8").rstrip() == "Please input the cryptic prophecy: The prophecy is fulfilled!";

def attempt(conn,offset):
	conn.recvline();
	conn.recvline();
	conn.recvline();
	conn.sendline("E");
	conn.recv();
	current = ''.join(random.choice("0123456789abcdef") for _ in range(16 + offset));
	now = "5w4p_4tt4ck}\n" + current;
	conn.sendline(current);
	h = conn.recvline().decode("utf-8").split(": ")[1].rstrip();
	swaps = h[:32] + h[11 * 32:12 * 32] + h[2 * 32:11 * 32] + h[32:2 * 32] + h[12 * 32:];
	# print(swaps);
	# print(current);
	res = ask(conn,swaps);

	if(res):
		# Yay P11[1] = IV[1] xor 16 xor P12[1]
		iv1 = int(h[:2],16);
		P10 = ord(now[3 + offset]);
		# print(current[3] + " " + str(P11))
		C9 = int(h[10 * 32:10 * 32 + 2],16);
		P9 = iv1 ^ ((29 - offset) % 16) ^ P10 ^ C9;
		# print(iv1);
		# print(P10);
		return chr(P9);
	return False;

conn.recvline();
ans = "";
for i in range(13):
	while True:
		res = attempt(conn,i);
		if(res):
			ans += res;
			break;

print(ans);
