import tools.AES as aes
import tools.RSA as rsa
import tools.keyGen as keygen


def main(message):
    KA_p, KA_s = keygen.rsa_keygen()
    KB_p, KB_s = keygen.rsa_keygen()

    aes_key = keygen.aes_keygen()

    # ======= CASOS DE USO =======
    # 1. Cifração de uma mensagem com AES
    ciphertext = aes.ctr_encryption(message, aes_key)
    print('Mensagem original: ' + message)
    print('Mensagem cifrada com AES: ' + ciphertext)
    print('-------------------------------')

    # 2. Cifração híbrida
    encrypted_key = rsa.oaep_encrypt(aes_key, KA_p)
    hybrid_ciphertext = (ciphertext, encrypted_key)
    print("Cifração híbrida: \nC =", hybrid_ciphertext)
    print('-------------------------------')

    # 3. Cifração híbrida com autenticação mútua (Usuário B enviando mensagem M para usuário A)
    encrypted_key_b = rsa.oaep_encrypt(str(encrypted_key), KB_s)
    print("Cifração híbrida com autenticação mútua: \nC = ", (ciphertext, encrypted_key_b, KB_p))
    print('-------------------------------')

    # 4. Geração de Assinatura de A (Usuário B enviando mensagem M para usuário A)
    signature = rsa.rsa_sign(ciphertext, KA_s)
    print("Geração de assinatura de A:", signature)
    print('-------------------------------')

    # 5. Verificação da assinatura (RSA_KA_p(RSA_KA_s(H(AES_k(M)))) = H(AES_k(M)) ?)
    verified = rsa.rsa_verify(ciphertext, signature, KA_p)
    print("Verificação de assinatura:", verified)


if __name__ == "__main__":
    message = input('Insira a mensagem para teste dos casos de uso: ')
    main(message)




