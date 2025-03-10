import os
from base64 import b64encode

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

# Generates an EC keypair
def generate_ec_keypair() -> dict:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return {
        "public": public_key,
        "private": private_key
    }

# Performs AES CBC encryption
def aes_encrypt(data: bytes) -> dict:
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad = padding.PKCS7(128).padder()
    padded_message = pad.update(data) + pad.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return {
        "key": key,
        "iv": iv,
        "ciphertext": ciphertext
    }

# Performs AES CBC decryption
def aes_decrypt(ciphertext: bytes, key, iv) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpad = padding.PKCS7(128).unpadder()
    decrypted_message = unpad.update(decrypted_padded_message) + unpad.finalize()

    return decrypted_message

# Performs ECDH
def create_shared_secret(our_private_key: EllipticCurvePrivateKey, their_public_key: EllipticCurvePublicKey) -> bytes:
    return our_private_key.exchange(ec.ECDH(), their_public_key)

# Key derivation
def do_kdf(shared_secret: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
    )
    return kdf.derive(shared_secret)

# AES key wrapping
def wrap_aes_key_with_derived_key(aes_key: bytes, derived_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(aes_key) + encryptor.finalize()

# AES key unwrapping
def unwrap_aes_key_with_derived_key(aes_key: bytes, derived_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(aes_key) + decryptor.finalize()




def main():
    alice_keypair = generate_ec_keypair()
    bob_keypair = generate_ec_keypair()

    shared_secret_alice = create_shared_secret(alice_keypair["private"], bob_keypair["public"])
    shared_secret_bob = create_shared_secret(bob_keypair["private"], alice_keypair["public"])
    print(f"Shared-Secret, using alice's private key and bob's public key - {b64encode(shared_secret_alice).decode()}")
    print(f"Shared-Secret, using bob's private key and alice's public key - {b64encode(shared_secret_bob).decode()}")

    message = "this is an important message".encode()

    ciphertext_json = aes_encrypt(data=message)
    aes_key = ciphertext_json["key"]
    iv = ciphertext_json["iv"]
    encrypted_message = ciphertext_json["ciphertext"]

    salt = b"alice-and-bob-4ever"
    derived_key = do_kdf(shared_secret_alice, salt)

    wrapped_aes_key = wrap_aes_key_with_derived_key(aes_key=aes_key, derived_key=derived_key)
    message = {
        "public_key": alice_keypair["public"],
        "ciphertext": encrypted_message,
        "wrapped_key": wrapped_aes_key,
        "iv": iv
    }

    unwrapped_aes_key = unwrap_aes_key_with_derived_key(message["wrapped_key"], derived_key)
    decrypted_message = aes_decrypt(message["ciphertext"], unwrapped_aes_key, message["iv"])
    print(f"Decrypted message: {decrypted_message.decode()}")


if __name__ == "__main__":
    main()