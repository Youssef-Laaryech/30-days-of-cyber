def encrypt(original):
    encrypted_word = ''
    for char in original:
        new_char = format(ord(char), '02x')
        encrypted_word += new_char
    return encrypted_word

def decrypt(original):
    decrypted_word = ''
    for i in range(0, len(original), 2):
        pair = original[i:i+2]
        new_char = chr(int(pair, 16))
        decrypted_word += new_char
    return decrypted_word
