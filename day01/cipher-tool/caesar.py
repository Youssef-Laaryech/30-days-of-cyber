def encrypt(original, shift):
    encrypted_word = ""
    for char in original:
        if char.isalpha():
            if 65 <= ord(char) <= 90:
                new_char = chr((ord(char) - 65 + shift) % 26 + 65)
                encrypted_word += new_char
            elif 97 <= ord(char) <= 122:
                new_char = chr((ord(char) - 97 + shift) % 26 + 97)
                encrypted_word += new_char
        else:
            encrypted_word += char
    return encrypted_word

def decrypt(original, shift):
    decrypted_word = ""
    for char in original:
        if char.isalpha():
            if 65 <= ord(char) <= 90:
                new_char = chr((ord(char) - 65 - shift) % 26 + 65)
                decrypted_word += new_char
            elif 97 <= ord(char) <= 122:
                new_char = chr((ord(char) - 97 - shift) % 26 + 97)
                decrypted_word += new_char
        else:
            decrypted_word += char
    return decrypted_word
