import os
from PIL import Image

# ---------- XOR Cipher ----------
def xor_cipher(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# ---------- LSB Encode ----------
def encode_message(image_path, message, output_path, key):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    img = Image.open(image_path).convert("RGBA")
    encoded = img.copy()
    width, height = img.size

    # Encrypt message
    encrypted = xor_cipher(message, key)
    encrypted_bytes = encrypted.encode('utf-8')
    msg_len = len(encrypted_bytes)

    # Store message length as 32 bits
    length_bits = f"{msg_len:032b}"
    message_bits = length_bits + ''.join(f'{byte:08b}' for byte in encrypted_bytes)
    total_bits = len(message_bits)

    if total_bits > width * height * 3:
        raise ValueError("Message too large to encode in this image.")

    data_index = 0
    for y in range(height):
        for x in range(width):
            pixel = list(img.getpixel((x, y)))
            for i in range(3):  # Only RGB
                if data_index < total_bits:
                    pixel[i] = (pixel[i] & ~1) | int(message_bits[data_index])
                    data_index += 1
            encoded.putpixel((x, y), tuple(pixel))
            if data_index >= total_bits:
                break
        if data_index >= total_bits:
            break

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    encoded.save(output_path)
    print(f" Message encoded and saved to: {output_path}")

# ---------- LSB Decode ----------
def decode_message(image_path, key):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    img = Image.open(image_path).convert("RGBA")
    width, height = img.size
    binary_data = ''

    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            for i in range(3):  # Only RGB
                binary_data += str(pixel[i] & 1)

    # First 32 bits = length
    msg_len = int(binary_data[:32], 2)
    message_bits = binary_data[32:32 + msg_len * 8]

    encrypted_bytes = [int(message_bits[i:i+8], 2) for i in range(0, len(message_bits), 8)]
    encrypted_message = bytes(encrypted_bytes).decode('utf-8')
    decrypted = xor_cipher(encrypted_message, key)
    return decrypted

# ---------- Main ----------
if __name__ == "__main__":
    print(" LSB Image Steganography with Key-Based Encryption")
    choice = input("Do you want to encode or decode? (e/d): ").strip().lower()

    if choice == 'e':
        input_path = input("Enter full path to input image: ").strip()
        output_path = input("Enter full path to save encoded image: ").strip()
        secret_message = input("Enter the secret message to encode: ").strip()
        key = input("Enter an encryption key (password): ").strip()

        try:
            encode_message(input_path, secret_message, output_path, key)
        except Exception as e:
            print(f" Error: {e}")

    elif choice == 'd':
        input_path = input("Enter full path to encoded image: ").strip()
        key = input("Enter the decryption key (password): ").strip()

        try:
            message = decode_message(input_path, key)
            print(f" Hidden Message: {message}")
        except Exception as e:
            print(f" Error: {e}")

    else:
        print(" Invalid choice. Please enter 'e' to encode or 'd' to decode.")
