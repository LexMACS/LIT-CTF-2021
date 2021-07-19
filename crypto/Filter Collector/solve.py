from Crypto.Util.number import getPrime
import random
import math
import cmath

from pwn import *;

from functools import reduce

def chinese_remainder(n, a):
    tot = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        tot += a_i * mul_inv(p, n_i) * p
    return tot % prod
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

p1 = (10000000**7 - 1) // (10000000 - 1)
p2 = (10000001**7 - 1) // (10000001 - 1)
p3 = (10000002**7 - 1) // (10000002 - 1)


def askHash(conn,a):
	print(conn.recv());
	conn.sendline(str(a));
	res = conn.recvline().decode("utf-8")[47:-1];
	return int(res);
	# return c

def tryHash(b,p):
	assert(math.gcd(p,7) == 1);
	conn = remote('filtercollector.litctf.live',1337);
	print(conn.recvline());
	print(conn.recv());
	conn.sendline(str(p));
	tot = 0;
	for i in range(7):
		tot += askHash(conn,b**i);
	tot %= p;
	return tot * mul_inv(7,p) % p;

l1 = ((tryHash(10000000,p1)))
l2 = ((tryHash(10000001,p2)))
l3 = ((tryHash(10000002,p3)))
print(bytes.fromhex(hex(chinese_remainder([p1,p2,p3],[l1,l2,l3]))[2:]))
