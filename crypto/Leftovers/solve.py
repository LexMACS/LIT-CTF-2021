import random
import binascii
import math
import sympy

from functools import reduce
def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
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

def lcm(a,b):
	return (a * b) // math.gcd(a,b);

random.seed(1337)

mods = [];
remainder = [16751036754, 7441743891, 13537409447, 12455208971, 16901669565, 15060041617, 15538665605, 192375025, 2176355740, 21877084789, 3184436468, 13214581420];
L = 1;

for i in range(12):
	x = random.randint(1,4e10);
	mods.append(sympy.prevprime(x));
	L = lcm(L,mods[-1]);

r = chinese_remainder(mods,remainder);
doNothing = 0;
for i in range(100000):
	try:
		cur = binascii.unhexlify(hex(L * i + r)[2:]).decode("utf-8")
		if(cur[0] == 'f' and cur[1] == 'l' and cur[2] == 'a' and cur[3] == 'g' and cur[4] == '{'):
			print(cur);
	except:
		doNothing = doNothing + 1;
