import hashlib
import sys
import base64

from tools.keyGen import rsa_keygen
from tools.keyGen import aes_keygen


def main(argv):
    if len(argv) != 1:
        print('Chamada inválida!')
        sys.exit(0)

    with open(argv[0], "r", encoding="utf-8") as f:
        message = f.read()

    public_key_a, private_key_a = rsa_keygen()
    public_key_b, private_key_b = rsa_keygen()

    aes_key = aes_keygen()

    old_hash = hashlib.sha3_256(message.encode()).digest()


