import hashlib
import os

from tools.keyGen import rsa_keygen


def apply_rsa(plaintext: int, key_tuple: (int, int)) -> int:
    # Perform RSA encryption or decryption
    n, x = key_tuple    # x can be either 'e' (for a public key) or 'd' (for a private key)
    return pow(plaintext, x, n)


def mgf1(seed: bytes, length: int) -> bytes:
    output = b""
    counter = 0
    while len(output) < length:
        output += hashlib.sha3_256(seed + int.to_bytes(counter, 4, 'big')).digest()
        counter += 1
    return output[:length]


def oaep_encrypt(plaintext: str, public_key: (int, int)) -> int:
    plaintext_bytes = plaintext.encode()
    n, e = public_key

    k = (n.bit_length() + 7) // 8
    m_len = k - 2 * hashlib.sha3_256().digest_size - 2

    if len(plaintext_bytes) > m_len:
        raise ValueError("Plaintext too long")

    # OAEP
    l_hash = hashlib.sha3_256(b"").digest()
    ps = b"\x00" * (k - len(plaintext_bytes) - 2 * hashlib.sha3_256().digest_size - 1)
    db = l_hash + ps + b"\x01" + plaintext_bytes
    seed = os.urandom(hashlib.sha3_256().digest_size)
    db_mask = mgf1(seed, k - hashlib.sha3_256().digest_size - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hashlib.sha3_256().digest_size)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    em = b"\x00" + masked_seed + masked_db

    # Apply RSA
    ciphertext = apply_rsa(int.from_bytes(em, "big"), public_key)

    return ciphertext


def oaep_decrypt(ciphertext: int, private_key: (int, int)) -> str:
    n, d = private_key

    # Decrypt the ciphertext using RSA
    em = apply_rsa(ciphertext, private_key).to_bytes((n.bit_length() + 7) // 8, 'big')

    # Perform OAEP unpadding
    l_hash = hashlib.sha3_256(b"").digest()
    k = len(em)
    hlen = hashlib.sha3_256().digest_size
    if k < 2 * hlen + 2:
        raise ValueError("Invalid ciphertext")
    masked_seed = em[1 : hlen + 1]
    masked_db = em[hlen + 1 :]
    seed_mask = mgf1(masked_db, hlen)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - hlen - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    l_hash_2 = db[: hlen]
    if l_hash_2 != l_hash:
        raise ValueError("Invalid ciphertext")

    # Extract the plaintext
    plaintext_bytes = db[hlen:].lstrip(b"\x00")

    # Convert the plaintext to string
    plaintext = plaintext_bytes.decode()

    return plaintext


public_key, private_key = rsa_keygen()
text = 'aaaaaaa bbbbbbbb ccccccccc ddddddddd eeeeeeee fffffff gggggggg'
cipher = oaep_encrypt(text, public_key)
print(cipher)
print(text)
print(oaep_decrypt(cipher, private_key))
