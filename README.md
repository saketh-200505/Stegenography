# Image Stegenography -
here is the simple python program that hides text(secret message) in the image.the program is based on least signifecant bit{LSBs} that alters the r,g,b values and convert secret text messages into binary values.the code is made simple to use for new users the code takes input image for hideing the data and secret message to hide inside the image and encrypt it using XOR Cipher.taking key value from the user.the decryption also included in the code choose decryption and provide the encrypted file path and enter the decryption key that is given in the encryption part

🔐 LSB Image Steganography with XOR Encryption
This Python project allows you to securely hide and extract secret messages inside image files using LSB (Least Significant Bit) steganography combined with XOR-based encryption.

🧠 Features

- XOR encryption using a password-based key
- LSB embedding of binary-encoded ciphertext into the image
- Dynamic message size tracking (via 32-bit header)
- Error handling for oversized messages and file access
- Simple CLI interface for encoding/decoding
  
📦 Requirements

- Python 3.x
- Pillow library (pip install pillow)
  
🚀 How to Use

- Run the script:
python stego_encryptor.py
- Choose operation:
- e to encode a message
- d to decode a hidden message
- Follow prompts to provide:
- Image path
- Message or encryption key
- Output path (for encoding)
  
🔐 How It Works

- The secret message is first XOR-encrypted using the key.
- The length of the encrypted byte stream is encoded in the first 32 bits.
- The resulting binary string is embedded into the image's RGB values using least significant bit (LSB) encoding.
- The decoding process reverses the steps using the correct password.
  
⚠️ Notes

- Works best with PNG or BMP images (uncompressed).
- Make sure the host image is large enough to store your message (width × height × 3 ≥ total bits).
- The key must match exactly during decryption to retrieve the original message.
