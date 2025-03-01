from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# --- Step 1: Generate RSA Keys ---
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# --- Step 2: Encrypt AES Key with RSA ---
def encrypt_aes_key(aes_key, rsa_public_key):
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

# --- Step 3: Decrypt AES Key with RSA ---
def decrypt_aes_key(encrypted_aes_key, rsa_private_key):
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

# --- Step 4: AES Encryption (CBC Mode) ---
def aes_encrypt(plain_text, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    padding = 16 - len(plain_text) % 16
    padded_message = plain_text + chr(padding) * padding
    encrypted_text = cipher.encrypt(padded_message.encode())
    return base64.b64encode(iv + encrypted_text).decode()

# --- Step 5: AES Decryption ---
def aes_decrypt(encrypted_text, aes_key):
    raw_data = base64.b64decode(encrypted_text)
    iv = raw_data[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(raw_data[16:])
    padding = decrypted_padded[-1]
    decrypted_text = decrypted_padded[:-padding].decode()
    return decrypted_text

# --- Execution ---
if __name__ == "__main__":
    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Generate AES Key (256-bit)
    aes_key = get_random_bytes(32)

    # Encrypt AES key using RSA public key
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

    # Decrypt AES key using RSA private key
    decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

    # Input message
    message = "This is a secret message!"

    # Encrypt message using AES
    encrypted_message = aes_encrypt(message, decrypted_aes_key)
    print(f"\n🔒 Encrypted Message: {encrypted_message}")

    # Decrypt message using AES
    decrypted_message = aes_decrypt(encrypted_message, decrypted_aes_key)
    print(f"\n🔓 Decrypted Message: {decrypted_message}")
