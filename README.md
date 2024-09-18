# NanoCrypt
NanoCrypt is a secure encryption and decryption application developed with PyQt5.

# Overview

NanoCrypt is a secure encryption and decryption application developed with PyQt5. It is designed to handle the encryption and decryption of files, text messages, and chats securely. The application employs robust cryptographic methods, including RSA (4096-bit) for asymmetric encryption and AES-256 GCM for symmetric encryption, ensuring the confidentiality and integrity of your data.
Features

### File Encryption/Decryption: 
Encrypt and decrypt files with the option to split large encrypted files into smaller parts for easier handling and transfer.

### Text Encryption/Decryption: 
Encrypt and decrypt text messages, with automatic copying of encrypted text to the clipboard.

### Chat Mode: 
Comming soon.

### Profile Management: 
Manage multiple profiles, each associated with a unique public key, enabling encryption for different recipients.

### Inactivity Timeout: 
Automatically locks the private key after a period of inactivity, requiring re-authentication.


# Installation
```
git clone https://github.com/your-username/cryptapp.git
cd cryptapp
```

```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

```
pip install -r requirements.txt
```

```
python main.py
```

