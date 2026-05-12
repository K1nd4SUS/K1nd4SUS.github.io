---
layout: /src/layouts/MarkdownPostLayout.astro
title: (crypto) K!nd4SUS CTF 2025 Writeups
author: K!nd4SUS
description: "Writeups for K!nd4SUS CTF '25 (crypto). Check the other categories on the website!"
pubDate: 2024-03-17
tags: ["writeup", "K!nd4SUS2025", "competition", "CTF", "crypto"]
image:
  url: "/images/writeup/bannercrypto.webp"
  alt: "CTF"
languages: ["python"]
---

## Crypto Writeups
---

### BackTheHank
> The Kindasus Bank prioritizes the security of its users by implementing two separate databases to store partial user information.<br>
> However, the bank has introduced two distinct login methods, which is kinda sus.<br>
> Embark on a journey through the bank's website!<br>
> http://chall.ctf.k1nd4sus.it:31337

The website's homepage displays the top clients of Kindasus Bank. Upon closer inspection of the Network tab, one can identify the endpoint:

`chall.ctf.k1nd4sus.it:31337/api/top-clients/MS01`

with the infamous MS01. By base64-decoding "MS01" one can see that it becomes "1-5", by modifying that input one can dump the whole database. A limit of 50 had been set in order to limit big requests, therefore going by 1-50, 51-100 and so on would have been a way to proceed, but "0-0-0" (best locket's password ever, isn't it?) and similar formatted strings, encoded in base64, were already providing access to the entire dump (1992 users).

Once the partial user information would have been recovered, one should have utilized the "Forgot Account Data?" option on the login page. This option would respond with "If the provided information is correct, recovery instructions will be sent." unless the correct information would have been indeed provided. By following this process, the flag could be obtained as a response.

At this juncture, there were two possible paths to pursue: password cracking or RSA module factorization. Fortunately, the vulnerability at hand was a fundamental one: two RSA modules shared a common factor, and for one of these modules, the username was also included in the partial information that had been previously recovered. By executing a script based on the greatest common divisor (GCD) across all the RSA modules, one could have identified both pieces of information necessary to conquer the challenge and acquire:

`KSUS{H4NK_B4CK3D_U_RSA_CLU3v3R}`

---
### Gravity Well
As the description says we have some control over the execution in the container:
- an environment variable;
- a python script.

Our control is limited by the many tests on the input and the `-I` (isolated mode) flag.
The "stick guy floating around" is a reference to XKCD comic number 353.
(Note that the server port ended with 353, just for verification)
One of Python easter eggs is the module `antigravity` (a convenient solution to a gravity well).
That module opens a webpage to the comic.
The imported `webbrowser` module uses the `BROWSER` environment variable.
That will be our attack point, payload:
`sh -c "cat flag.txt; echo %s"`
while the script can be the innocent looking
`import antigravity`.

---
### Key in the Haystack
The haystack is just a polynomial: product of (x + p) over p random primes.
The RSA factors are the only (not necessarily, but quite surely) repeated roots of the polynomial.
The gcd of the polynomial with its derivative will be (x + p) * (x + q), where p and q are the factors.
This allows us to recover both the modulus and the private exponent.
Alternatively, one could find all the roots and try their pairwise combinations to decrypt.
That may be feasible, but - having the "accidentally" repeated roots - it's not necessary.
Care must be taken in computing the gcd: floats don't have enough range, and fractions may be too slow.

```python
from base64 import b64decode
from gmpy2 import gcd
from math import isqrt

b64dec = lambda y: int(b64decode(y).hex(), 16)

c = input("ciphertext>").split()[-1]
c = int(c, 16)

size = input("size>").split()[-1]
size = int(size)

r = []
for _ in range(size):
	r.append(b64dec(input()))

print("\ncomputing:")

print("derivative...")
s = []
for k, x in enumerate(r, 1):
	deg = size - k
	s.append(deg * x)
if s:
	assert not s[-1]
	s.pop()

def poly_gcd(a, b):
	if len(a) < len(b):
		a, b = b, a
	counter = 0
	while b:
		assert a[0]
		assert b[0]
		if len(a) < len(b):
			a, b = b, a
			counter -= 1
		counter += 1
		if counter > 1:
			d = gcd(*a)
			for i in range(len(a)):
				a[i] //= d
			d = gcd(*b)
			for i in range(len(b)):
				b[i] //= d
			counter = 0
		d = gcd(a[0], b[0])
		qa = b[0] // d
		qb = a[0] // d
		a[0] = 0
		for i in range(1, len(b)):
			a[i] = (qa * a[i]) - (qb * b[i])
		for i in range(len(b), len(a)):
			a[i] *= qa
		cleared = 0
		for x in a:
			if x:
				break
			else:
				cleared += 1
		a, b = b, a[cleared:]
	return a

print("gcd...")
a, b, n = poly_gcd(r, s)
#print("---", a)
#print("---", b)
#print("---", n)
b, rb = divmod(b, a)
assert not rb
n, rn = divmod(n, a)
assert not rn

print("modulus...")
print(n)

print("factors...")
avg, r = divmod(-b, 2)
assert not r
hd = isqrt(avg**2 - n)
x1 = avg - hd
x0 = avg + hd
p, q = -x0, -x1
print(p)
print(q)
assert p > 0
assert q > 0
assert n == p * q

print("private exponent...")
e = pow(65537, -1, (p - 1) * (q - 1))
print(e)

print("message...")
m = pow(c, e, n)
h = hex(m)[2:]
if len(h) % 2:
	h = '0' + h
m = bytes.fromhex(h)
print(m)
print(m.decode())
```

---
### Key in the Big Haystack
Same as before (gcd between the polynomial and its derivative), but a simple Euclidean algorithm is too slow.
A solution could have been binary search for the zeros.
But this time non-double solution are pairwise at distance 2 so a negative value is difficult to find.
Increasing / decreasing could be used instead of positive / negative.
That just means binary search on the derivative: we are interested to solutions that are an odd integer.
Newton's method may also be a usefool tool (do integer divisions; floats are bad here).
The attached solver uses a different approach that makes the original idea competitive again.
We can compute the same polynomial gcd, but over finite fields Z/pZ, for some primes p.
The primes should be big, so the product is over `2**1024` - the infinity norm of (x + p) * (x + q) - with only a few primes (and few gcd computations).
The primes should be small, so that the operations with big nums are not expensive.
A good compromise is to take the 19 biggest primes less than `2**63` (taking only 17 is enough).
Then the second-degree polynomial can be recovered by Chinese Reminder Theorem, using the extended Euclidean algorithm for integers.


```python
from base64 import b64decode
from gmpy2 import is_prime, gcdext
from math import isqrt

b64dec = lambda y: int(b64decode(y).hex(), 16)
primes = [(1<<63) - k for k in range(1, 800, 2)]
primes = [x for x in primes if is_prime(x)]
prime_name = lambda p: f"P{(1<<63) - p:03d}"

c = input("ciphertext>").split()[-1]
c = int(c, 16)

size = input("size>").split()[-1]
size = int(size)

r = []
for _ in range(size):
	r.append(b64dec(input()))

print("\ncomputing:")

print("derivative...")
s = []
for k, x in enumerate(r, 1):
	deg = size - k
	s.append(deg * x)
if s:
	assert not s[-1]
	s.pop()

r = tuple(r)
s = tuple(s)

def poly_gcd(a, b, p):
	# reduce a
	a = [x % p for x in a]
	cleared = 0
	for x in a:
		if x:
			break
		else:
			cleared += 1
	a = a[cleared:]
	# reduce b
	b = [x % p for x in b]
	cleared = 0
	for x in b:
		if x:
			break
		else:
			cleared += 1
	b = b[cleared:]
	# main loop
	if len(a) < len(b):
		a, b = b, a
	while b:
		assert a[0]
		assert b[0]
		if len(a) < len(b):
			a, b = b, a
		q = a[0] * pow(b[0], -1, p)
		q %= p
		a[0] = 0
		for i in range(1, len(b)):
			x = a[i]
			y = (q * b[i]) % p
			a[i] = x - y if x >= y else x + p - y
		cleared = 0
		for x in a:
			if x:
				break
			else:
				cleared += 1
		a, b = b, a[cleared:]
	return a

print("gcd...")
records = []
for p in primes:
	print(f"\t{prime_name(p)}: ", end="", flush=True)
	ans = poly_gcd(r, s, p)
	n_ans = len(ans) - 1
	print(n_ans)
	if n_ans != 2:
		continue
	a, b, n = poly_gcd(r, s, p)
	ai = pow(a, -1, p)
	b = (b * ai) % p
	n = (n * ai) % p
#	print("---", f"{b = }")
#	print("---", f"{n = }")
	records.append((p, b, n))

print("recompose...")
b, n = 0, 0
mod = 1
for p, bp, np in records:
	one, cp, cmod = map(int, gcdext(p, mod))
	assert one == 1
	assert one == cp * p + cmod * mod
	n *= cp * p
	n += cmod * mod * np
	b *= cp * p
	b += cmod * mod * bp
	mod *= p
	n %= mod
	b %= mod
#	print("---", f"{b = }")
#	print("---", f"{n = }")
#	print("---", f"{mod = }")
#	print("---")

print("modulus...")
print(n)

print("factors...")
avg, r = divmod(-b, 2)
assert not r
hd = isqrt(avg**2 - n)
x1 = avg - hd
x0 = avg + hd
p, q = -x0, -x1
print(p)
print(q)
assert p > 0
assert q > 0
assert n == p * q

print("private exponent...")
e = pow(65537, -1, (p - 1) * (q - 1))
print(e)

print("message...")
m = pow(c, e, n)
h = hex(m)[2:]
if len(h) % 2:
	h = '0' + h
m = bytes.fromhex(h)
print(m)
print(m.decode())
```

---
### Lightning-fast Scrambling
The name reads LFS? and this is just a LFSR where you have to guess the last part of the key.
The LFSR works 8 bits per step and the key is the first 8 bytes of the produced keystream.
The plaintext is the flag and begins with "KSUS{" this gives 5 bytes of the key.
The remaining 3 bytes can be bruteforced.
The easy way is to exploit the low entropy of the rest of the flag (hex digits: 4 bits per byte), at most 4096 attempts are required.
It is indeed not possible to recover the passphrase but it doesn't matter

```python
from lfs import *
from itertools import product

challenge = input("challenge > ")
e, hash = map(base64_decode, challenge.split('#'))
prefix = "KSUS{".encode()

for t in product("0123456789abcdef", repeat=3):
	missing_fragment = "".join(t)
	base_message = prefix + missing_fragment.encode()
	key_stream = [x ^ y for x, y in zip(e, base_message)]
	key = 0
	for x in reversed(key_stream):
		key <<= 8
		key |= x
	message = scramble(e, key)
	if hash == digest(message):
		flag = message.decode()
		break
else:
	assert False

print("key :", key)
print("flag :", flag)
```

---
### Feistel <3

The challenge involves a Feistel network used in CBC mode to encrypt the flag. In detail, the encryption function uses a 128-bit key $k$ that's split into 8 round keys $k_i$, and employs the F function:

$$F(B, k_{i}, N) = B + (65537^{k_{i}} \mod N) \mod 65536$$

We can summarize the operations in each round with these equations:

$$
\begin{align*}
    L_{i} &= L_{i-1} \oplus M_{i-1} \\ 
    M_{i} &= F(R_{i-1}, k_{i}, N)\\
    R_{i} &= M_{i-1} \oplus k_{i} \\
\end{align*}
$$

The oracle allows us to encrypt single blocks of 2 bytes, with a shortcut occurring when the block $L_{i}$ of the current round equals `0xffff`. Given this structure, we can extract each round key $k_i$ by crafting a plaintext that will produce `0xffff` at round $i$. We can then retrieve the key with:

$$M_{i-1} \oplus R_{i} = k_{i}$$

Having all the round keys $k_{j}$ for $j<i$, we can forge the necessary plaintext to trigger a shortcut at round $i$ by selecting a hex value where $L \oplus M = $ `0xffff`, and then decrypt from round $i-1$ to $0$ using the known round keys.

#### Exploit
```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *

def xor_bytes(bytes_a, bytes_b):
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b)).ljust(2, b'\x00')

def f(sub_block, round_key, modulus):
    sub_block = bytes_to_long(sub_block)
    round_key = bytes_to_long(round_key)
    res = (sub_block + pow(65537, round_key, modulus)) % (1<<17-1)
    return long_to_bytes(res).ljust(2, b'\x00')

def inv_f(sub_block, round_key, modulus):
    sub_block = bytes_to_long(sub_block)
    round_key = bytes_to_long(round_key)
    res = (sub_block - pow(65537, round_key, modulus)) % (1<<17-1)
    return long_to_bytes(res).ljust(2, b'\x00')

def decrypt_block(block, key, modulus, rounds=8):
    sub_block_1 = block[:2].ljust(2, b'\x00')
    sub_block_2 = block[2:4].ljust(2, b'\x00')
    sub_block_3 = block[4:].ljust(2, b'\x00')
    for i in range(rounds-1, -1, -1):
        round_key = key[i*2:i*2+2]
        prev_1 = xor_bytes(sub_block_1, xor_bytes(sub_block_3, round_key)) 
        prev_2 = xor_bytes(sub_block_3, round_key)
        prev_3 = inv_f(sub_block_2, round_key, modulus)
        sub_block_1 = prev_1
        sub_block_2 = prev_2
        sub_block_3 = prev_3
    return sub_block_1 + sub_block_2 + sub_block_3

def decrypt(ciphertext, key, modulus):
    iv = bytes.fromhex(ciphertext[:12])
    ciphertext = bytes.fromhex(ciphertext[12:])
    blocks = [ciphertext[i:i+6] for i in range(0, len(ciphertext), 6)] 
    res = b""
    for i in range(len(blocks)):
        block = decrypt_block(blocks[i], key, modulus)
        if i == 0: block = xor_bytes(block, iv)
        else: block = xor_bytes(block, blocks[i-1])
        res += block
    return res

def get_key(key, modulus, round):
    if key == b"":
        target = "0ffff000aaaa"
    else:
        target = decrypt_block(bytes.fromhex("0ffff000aaaa"), key, modulus, round-1).hex()
    conn.sendlineafter(b"> ", b"1")
    conn.sendlineafter(b"Enter your fantastic plaintext (in hex): ", target.encode())
    conn.recvuntil(b"Here it is: ")
    new_ct = conn.recvline().decode().strip()
    l = bytes.fromhex(target[:4])
    m = bytes.fromhex(target[4:8])
    r = bytes.fromhex(target[8:])
    for i in range(round-1):
        l_n = xor_bytes(l, m)
        m_n = f(r, key[i*2:i*2+2], modulus)
        r_n = xor_bytes(m, key[i*2:i*2+2])
        l = l_n
        m = m_n
        r = r_n
    round_key = xor_bytes(m, bytes.fromhex(new_ct[8:]))
    return round_key

conn = remote(...)
conn.recvuntil(b"flag = ")
FLAG = conn.recvline().decode().strip()
conn.recvuntil(b"N = ")
modulus = int(conn.recvline().decode().strip())
key = b""
for i in range(8):
    key += get_key(key, modulus, i+1)
print(key.hex())
print(decrypt(FLAG, key, modulus))
```

---
### Matrices Matrices Matrices
The challenge revolves around the Learning With Error problem, having only the public key $(A, b)$. The elements of the public key are linked by the relation:

$$A \times s + e = b$$

Given $m=70$ and $n=30$, $A$ is the $m \times n$ public matrix, $s$ the $n \times 1$ secret vector, $e$ the $m \times 1$ error vector and $b$ the $n \times 1$ public vector. The idea is to represent the cryptosystem through a lattice and recover the error vector $e$ solving the SVP (Shortest Vector Problem) with a reduction of the lattice. So we can rewrite the initial relation as:

$$
\begin{pmatrix}
A & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s \\
-1
\end{pmatrix}
= \begin{pmatrix}
-e \\
-t
\end{pmatrix}
$$

The vector $(-e, -t)$ belongs to the lattice with basis $\begin{pmatrix} A&b\\ 0&t \end{pmatrix}$, since it can be written as a linear combination. We can perform a gaussian elimination on the columns of A to find an invertible matrix $U$ such that:

$AU = \begin{pmatrix}
I_{n \times n} \\
A'
\end{pmatrix}$

This means that we can rewrite the previous multiplication as:
$$
\begin{pmatrix}
A & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s \\
-1 
\end{pmatrix}
= \begin{pmatrix}
A & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
U & 0 \\
0 & 1 
\end{pmatrix}
\begin{pmatrix}
U^{-1} & 0 \\
0 & 1
\end{pmatrix}
\begin{pmatrix}
s \\
-1
\end{pmatrix}
= \begin{pmatrix}
\begin{pmatrix}
I_n \\
A'
\end{pmatrix} & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s' \\
-1
\end{pmatrix}
$$

So the problem now becomes finding a $s'$ such that the following equation it's true:

$$
\begin{pmatrix}
\begin{pmatrix}
I_n \\
A'
\end{pmatrix} & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s' \\
-1
\end{pmatrix}
= \begin{pmatrix}
-e \\
-t
\end{pmatrix}
$$

The matrices are considered over $\mathbb{Z}_{271}$, but since we are working with a lattice now, we have to turn this in an identity of matrices over $\mathbb{Z}$, which basically means adding to the equation that defines $e$ a vector of coordinates that are a multiple of $q=271$:

$$
-e = \begin{pmatrix}
I_n \\
A'
\end{pmatrix}
s' - b + \begin{pmatrix}
0_n \\
q I_{m-n} k
\end{pmatrix}
$$

Given this equation and the previous one, we can define the following matrix $B$

$$
B = \begin{pmatrix}
\begin{pmatrix}
I_{n} \\
A'
\end{pmatrix} & b & \begin{pmatrix}
0_n \\
q I_{m-n}
\end{pmatrix} \\
0 & t & 0
\end{pmatrix}
$$

Now we have just to find the shortest vector of the lattice defined by the columns of $B$. If there are no other significantly short vectors in the lattice, we will find a vector in the form $\begin{pmatrix} -e, -t \end{pmatrix}$ or $\begin{pmatrix} e, t \end{pmatrix}$, obtained from a linear combination with $B$:

$$
B \begin{pmatrix}
s' \\
-1 \\
k
\end{pmatrix}
= \begin{pmatrix}
-e \\
-t
\end{pmatrix}
$$

Once we have obtained $e$, we can simply retrieve $s$ by subtracting $e$ from $b$ and then solving the system of equations system.

#### Exploit
The solution explained is achieved using sage, building directly $B$ calculating the Reduced Row Echelon Form on the transposition of A and then transpositioning again to obtain 
<br> $\begin{pmatrix} I_n \\ A' \end{pmatrix}$ and using $t=1$. 
Then the shortest vector of the lattice defined by the columns of $B$ is obtained applying Lenstra-Lenstra-Lovàsz on transposed $B$, getting $(e,t)$ as the first row of the reduced matrix.

```python
from sage.all import GF, identity_matrix, Matrix, ZZ

q = 271
qf = GF(q)
m = 70
n = 30

def retrieve_s(A, b):
    left = A.transpose().rref().transpose()
    zero_vector = Matrix(qf, [[0 for _ in range(n)]])
    left = left.stack(zero_vector)
    
    middle = b.stack(Matrix(qf, [[1]]))
    
    zero_matrix = Matrix(ZZ, [[0 for _ in range(m-n)] for _ in range(n)])
    q_identity_matrix = q*identity_matrix(ZZ, m - n)
    zero_vector = Matrix(ZZ, [[0 for _ in range(m-n)]])
    right = zero_matrix.stack(q_identity_matrix).stack(zero_vector)

    B = left.augment(middle).change_ring(ZZ).augment(right)
    reduced = B.transpose().LLL()
    e = reduced[0][:-1]
    e = Matrix(qf, [[e[i]] for i in range(m)])

    a_times_s = b - e
    s = A.solve_right(a_times_s)
    return s

a=[...]
b=[...]

a = Matrix(qf, a)
b = Matrix(qf, b)
s = retrieve_s(a, b)
flag = [chr(x) for x in s.list()]
print("".join(flag))
```