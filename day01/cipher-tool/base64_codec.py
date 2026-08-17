alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def encrypt(original):
    encrypted_word = ''
    binary_char = ''
    for char in original:
        binary_char_chunk = format(ord(char), '08b')
        binary_char += binary_char_chunk
    while len(binary_char) % 6 != 0:
        binary_char += '0'
    for i in range(0, len(binary_char), 6):
        chunk = binary_char[i:i+6]
        index = int(chunk, 2)
        encrypted_word += alphabet[index]
    padding = len(original) % 3
    if padding == 1:
        encrypted_word += "=="
    elif padding == 2:
        encrypted_word += "="
    return encrypted_word

def decrypt(original):
    decrypted_word = ''
    original = original.rstrip("=")
    binary_char = ''
    for char in original:
        binary_char_chunk = format(alphabet.index(char), '06b')
        binary_char += binary_char_chunk
    for i in range(0, len(binary_char), 8):
        chunk = binary_char[i:i+8]
        if len(chunk) == 8:
            decrypted_word += chr(int(chunk, 2))
    return decrypted_word
