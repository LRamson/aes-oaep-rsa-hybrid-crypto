import secrets


def aes_keygen() -> str:
    key = secrets.token_hex(16)
    return key


def rsa_keygen() -> str:
    return ''