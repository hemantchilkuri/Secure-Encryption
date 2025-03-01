# Secure Encryption Program 🛡️🔒

This project demonstrates AES-256 and RSA-2048 encryption in Python.

## Features
✅ Uses AES (256-bit) for message encryption  
✅ Uses RSA (2048-bit) for secure key exchange  
✅ Encrypts and decrypts messages easily  

## Installation
1. Install Python (if not installed): [Python Download](https://www.python.org/downloads/)
2. Ensure you have Python installed (Python 3.8+ recommended).
1️⃣ Install Dependencies
pip install pycryptodome
2️⃣ Clone the Repository
git clone https://github.com/YourUsername/Secure-Encryption.git
cd Secure-Encryption

## Usage 🚀
Run the script using the following commands:
1️⃣ Generate RSA Keys 🔑
python secure_encryption.py --generate-keys
This will generate private.pem and public.pem for encryption.
2️⃣ Encrypt a Message 🔒
python secure_encryption.py --encrypt "Hello, this is a secret!"
You will be prompted to enter a password for added security.
3️⃣ Decrypt a Message 🔓
python secure_encryption.py --decrypt "PASTE_ENCRYPTED_TEXT_HERE"
Enter the same password used during encryption.
4️⃣ Encrypt a File 🗂️
python secure_encryption.py --encrypt-file "example.txt" --output "example_encrypted.dat"
5️⃣ Decrypt a File 📂
python secure_encryption.py --decrypt-file "example_encrypted.dat" --output "example_decrypted.txt"

## How It Works 🛡️
AES Key Generation:
The user enters a password.
AES key is derived using PBKDF2 with a random salt.
Message/File Encryption:
AES-256 in CBC mode is used.
Encrypted data is base64 encoded for easy storage.
RSA Encryption:
The AES key is encrypted with RSA.
Only the private key can decrypt it.
Decryption Process:
The user enters the same password.
AES key is reconstructed and used to decrypt.
Security Considerations 🔍
Never share your private key (private.pem)!
Use a strong password for deriving AES keys.
RSA-2048 is secure, but you can upgrade to RSA-4096 for added safety.
Always keep backups of your encryption keys!

## Contributing 🤝
Feel free to contribute! Fork the repository and submit a pull request. 🚀

 ## License 📜
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Disclaimer ⚠️  
This project is for **educational and research purposes only**. The author is **not responsible** for any misuse of this code.  

By using this software, you agree to:  
✅ Use it **only for lawful and ethical purposes**.  
✅ **Not engage in illegal activities** or unauthorized data access.  
✅ Ensure compliance with local **laws and regulations**.  

🔹 **Use responsibly! Security is about protection, not exploitation.**  

## Author
👤 ** Hemant Chilkuri **  
🔗 [GitHub Profile](https://github.com/hemantchilkuri)  
