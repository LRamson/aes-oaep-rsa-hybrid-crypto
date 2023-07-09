import base64
import hashlib
import os


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

    # OAEP
    # Hash the label
    l_hash = hashlib.sha3_256(b"").digest()
    # Generate padding string
    ps = b"\x00" * (k - len(plaintext_bytes) - 2 * hashlib.sha3_256().digest_size - 1)
    # Form data block
    db = l_hash + ps + b"\x01" + plaintext_bytes
    # Generate random seed
    seed = os.urandom(hashlib.sha3_256().digest_size)
    # Generate mask for the data block
    db_mask = mgf1(seed, k - hashlib.sha3_256().digest_size - 1)
    # Mask the data block (XOR w/ mask)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    # Generate mask for seed
    seed_mask = mgf1(masked_db, hashlib.sha3_256().digest_size)
    # Mask the seed
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    # Encoded message is 0x00||masked_seed||masked_db
    em = b"\x00" + masked_seed + masked_db

    # Apply RSA
    ciphertext = apply_rsa(int.from_bytes(em, "big"), public_key)

    return ciphertext


def oaep_decrypt(ciphertext: int, private_key: (int, int)) -> str:
    n, d = private_key

    # Decrypt the ciphertext using RSA
    em = apply_rsa(ciphertext, private_key).to_bytes((n.bit_length() + 7) // 8, 'big')

    # Perform OAEP unpadding
    # Hash the label
    l_hash = hashlib.sha3_256(b"").digest()
    k = len(em)
    hlen = hashlib.sha3_256().digest_size
    if k < 2 * hlen + 2:
        raise ValueError("Invalid ciphertext")

    # Split the encoded message (0x00||masked_seed||masked_db)
    masked_seed = em[1: hlen + 1]
    masked_db = em[hlen + 1:]
    # Generate seed mask
    seed_mask = mgf1(masked_db, hlen)
    # Recover the seed -> seed = masked_seed XOR seed_mask
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    # Generate DB mask
    db_mask = mgf1(seed, k - hlen - 1)
    # Recover the db -> db = masked_db XOR db_mask
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # Extract and test l_hash
    l_hash_2 = db[: hlen]
    if l_hash_2 != l_hash:
        raise ValueError("Invalid ciphertext")

    # Extract the plaintext
    plaintext_bytes = db[hlen:].lstrip(b"\x00")

    # Convert the plaintext to string
    plaintext = plaintext_bytes.decode()

    return plaintext


def rsa_sign(message: str, private_key: (int, int)) -> str:
    plaintext = message.encode()

    hash_value = hashlib.sha3_256(plaintext).digest()
    signature = apply_rsa(int.from_bytes(hash_value, "big"), private_key)
    signature_base64 = base64.b64encode(signature.to_bytes((private_key[0].bit_length() + 7) // 8, 'big')).decode()
    return signature_base64


def rsa_verify(message: str, signature_base64: str, public_key: (int, int)) -> bool:
    plaintext = message.encode()

    hash_value = hashlib.sha3_256(plaintext).digest()
    signature = int.from_bytes(base64.b64decode(signature_base64.encode()), 'big')
    decrypted_signature = apply_rsa(signature, public_key)
    decrypted_signature_bytes = decrypted_signature.to_bytes((decrypted_signature.bit_length() + 7) // 8, 'big')\
        .lstrip(b'\x00')    # Strips the padding

    return decrypted_signature_bytes == hash_value

