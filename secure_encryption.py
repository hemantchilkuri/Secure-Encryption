import argparse
import base64
import os
import getpass
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

"""
Secure Encryption Script with Password Protection
Author: Hemantchilkuri
GitHub: https://github.com/hemantchilkuri/Secure-Encryption
Date: 2025-03-01
Description: Encrypt and decrypt messages & files using AES-256 and RSA-2048 with password protection.

⚠️ Disclaimer:
This script is for educational purposes only. Do not use it for illegal activities.
The author is not responsible for any misuse.
"""

SALT_SIZE = 16
AES_KEY_SIZE = 32
PBKDF2_ITERATIONS = 100000

# --- RSA Key Generation ---
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# --- Derive AES Key from Password ---
def derive_aes_key(password):
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS)
    return key, salt

# --- Encrypt AES Key with RSA ---
def encrypt_aes_key(aes_key, rsa_public_key):
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(aes_key)

# --- Decrypt AES Key with RSA ---
def decrypt_aes_key(encrypted_aes_key, rsa_private_key):
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_aes_key)

# --- AES Encryption (CBC Mode) ---
def aes_encrypt(plain_text, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    padding = 16 - len(plain_text) % 16
    padded_message = plain_text + chr(padding) * padding
    encrypted_text = cipher.encrypt(padded_message.encode())
    return base64.b64encode(iv + encrypted_text).decode()

# --- AES Decryption ---
def aes_decrypt(encrypted_text, aes_key):
    raw_data = base64.b64decode(encrypted_text)
    iv = raw_data[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(raw_data[16:])
    padding = decrypted_padded[-1]
    return decrypted_padded[:-padding].decode()

# --- Encrypt a File ---
def encrypt_file(input_file, output_file, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_file, "rb") as f:
        file_data = f.read()

    padding = 16 - len(file_data) % 16
    file_data += bytes([padding]) * padding
    encrypted_data = cipher.encrypt(file_data)

    with open(output_file, "wb") as f:
        f.write(iv + encrypted_data)

    print(f"✅ File Encrypted: {output_file}")

# --- Decrypt a File ---
def decrypt_file(input_file, output_file, aes_key):
    with open(input_file, "rb") as f:
        raw_data = f.read()

    iv = raw_data[:16]
    encrypted_data = raw_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_data)

    padding = decrypted_padded[-1]
    decrypted_data = decrypted_padded[:-padding]

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ File Decrypted: {output_file}")

# --- Command-Line Interface ---
def main():
    parser = argparse.ArgumentParser(description="AES & RSA Encryption Tool with Password Protection")

    parser.add_argument("--generate-keys", action="store_true", help="Generate RSA public/private keys")
    parser.add_argument("--encrypt", type=str, help="Message to encrypt")
    parser.add_argument("--decrypt", type=str, help="Message to decrypt")
    parser.add_argument("--encrypt-file", type=str, help="File to encrypt")
    parser.add_argument("--decrypt-file", type=str, help="File to decrypt")
    parser.add_argument("--output", type=str, help="Output file for encryption/decryption")

    args = parser.parse_args()

    # Generate RSA keys if requested
    if args.generate_keys:
        private_key, public_key = generate_rsa_keys()
        with open("private.pem", "wb") as priv_file, open("public.pem", "wb") as pub_file:
            priv_file.write(private_key)
            pub_file.write(public_key)
        print("✅ RSA Keys generated: private.pem & public.pem")
        return

    # Load RSA Keys
    try:
        with open("private.pem", "rb") as priv_file, open("public.pem", "rb") as pub_file:
            private_key = priv_file.read()
            public_key = pub_file.read()
    except FileNotFoundError:
        print("❌ RSA keys not found! Run with `--generate-keys` first.")
        return

    # Ask for a password to derive AES key
    password = getpass.getpass("🔑 Enter a password: ")
    aes_key, salt = derive_aes_key(password)

    # Encrypt AES key using RSA
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

    # Encrypt a message
    if args.encrypt:
        encrypted_message = aes_encrypt(args.encrypt, aes_key)
        print(f"🔒 Encrypted Message: {encrypted_message}")
        return

    # Decrypt a message
    if args.decrypt:
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        decrypted_message = aes_decrypt(args.decrypt, decrypted_aes_key)
        print(f"🔓 Decrypted Message: {decrypted_message}")
        return

    # Encrypt a file
    if args.encrypt_file and args.output:
        encrypt_file(args.encrypt_file, args.output, aes_key)
        return

    # Decrypt a file
    if args.decrypt_file and args.output:
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        decrypt_file(args.decrypt_file, args.output, decrypted_aes_key)
        return

if __name__ == "__main__":
    main()
