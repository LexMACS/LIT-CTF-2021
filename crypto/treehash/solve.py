from Crypto.Util.number import inverse
from sympy import prevprime
from random import randint, shuffle
import sys

#init

sys.setrecursionlimit(1000)

#vars

n = 100
m = prevprime(n ** (n - 2))
k = 65537

mx = 80
flagkey = b"This piece of text is the flag key wow omg!"

print('Flag key: ' + str(flagkey))
print('Flag key hex: ' + flagkey.hex())

#funcs

def hexToStr(s):
    try:
        return bytes.fromhex(s).rstrip(b'\x00')
    except:
        return ""

def strToInt(s):
    return int.from_bytes(s, "little")
    
def intHash(x):
    return pow(x, k, m)

def intToArray(x):
    a = []
    for i in range(n - 2):
        a.append(x % n)
        x //= n
    return a

def arrayToTree(a):
    d = [0] * n
    for i in a:
        d[i] += 1

    a.append(a[-1])

    j, l = 0, 0
    e = []
    for i in a:
        while d[j] != 0 or i == j:
            j += 1
        if d[l] != 0 or i == l:
            l = j
        
        e.append((i, l))

        d[i] -= 1
        d[l] -= 1

        if d[i] == 0 and i < j:
            l = i

    return e

def dfs(g, c, p):
    ret = c
    for i in g[c]:
        if i != p:
            ret = max(ret, dfs(g, i, c))

    return ret

def treeHash(e):
    g = [[] for i in range(n)]

    for i in e:
        g[i[0]].append(i[1])
        g[i[1]].append(i[0])

    ret = []
    for i in e:
        ret.append(min(dfs(g, i[0], i[1]), dfs(g, i[1], i[0])))

    return ret

def getMaxList(s):
    x = strToInt(s)
    y = intHash(x)
    a = intToArray(y)
    e = arrayToTree(a)
    return treeHash(e)

#exploit

#get sorted list of values

a = getMaxList(flagkey)

print('Max array: \n' + str(a))

num = 1 << (8 * mx)
while num >= (1 << (8 * mx)):
    #lol i just copied https://codeforces.com/contest/1041/problem/E to construct random tree, likely not flagkey

    b, d, p, v = [0] * n, [0] * n, [0] * n, [False] * n

    for i in a:
        b[i] += 1

    j, x, y = 0, -1, -1
    for i in range(n - 1):
        if b[i] > 0:
            if x != -1:
                d[i] += 1
                d[x] += 1
                p[x] = i
            else:
                y = i

            x = i
            b[i] -= 1
            v[i] = True

        t = []

        while b[i] > 0:
            while v[j]:
                j += 1

            t.append(j)

            b[i] -= 1
            v[j] = True

        shuffle(t)

        for l in t:
            d[l] += 1
            d[x] += 1
            p[x] = l

            x = l

    d[x] += 1
    d[n - 1] += 1
    p[x], p[n - 1] = n - 1, -1

    #print('Parent array: \n' + str(p))

    #get prufer code from parent array

    f = []

    j = y
    for i in range(n - 2):
        x = p[j]
        f.append(x)

        d[x] -= 1
        if d[x] == 1 and x < y:
            j = x
        else:
            y += 1
            while d[y] != 1:
               y += 1

            j = y

    #print('Prufer array: \n' + str(f))

    #convert prufer code to number

    x, y = 0, 1
    for i in f:
        x += i * y
        y *= n

    #print('Prufer number: ' + str(x))

    #get string number

    num = pow(x, inverse(k, m - 1), m)

print('Parent array: \n' + str(p))
print('Prufer array: \n' + str(f))
print('Prufer number: ' + str(x))
print('String number: ' + str(num))

#convert number to string

s = num.to_bytes((7 + num.bit_length()) // 8, 'little')

print('String len: ' + str(len(s)))
print('String: ' + str(s))
print('String hex: ' + s.hex())
