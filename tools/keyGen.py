import secrets
import random
from math import gcd
from egcd import egcd

def aes_keygen() -> str:
    key = secrets.token_hex(16)
    return key


def rsa_keygen() -> ((int, int), (int, int)):
    p = generate_prime_number()
    q = generate_prime_number()
    n = p * q
    phi = (p-1) * (q-1)

    while True:
        e = random.randint(2, phi-1)
        if gcd(e, phi) == 1:
            break

    d = egcd(e, phi)[1] % phi
    if d < 0:
        d += phi

    private_key = (n, e)
    public_key  = (n, d)

    return public_key, private_key


def is_prime(n: int, k: int = 40) -> bool:
    if n % 3 == 0 or n % 5 == 0 or n % 7 == 0:  #
        return False

    # Perform the Miller-Rabin primality test
    d = n - 1
    s = 0
    while d & 1 == 0:   # Loop to determine s in n-1 = 2^s * d
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime_number(length: int = 1024) -> int:
    while True:
        p = random.getrandbits(length)
        p |= (1 << length - 1) | 1  # Set MSB and LSB to 1, which makes so the number is odd and 1024 bit long
        if is_prime(p):
            return p
