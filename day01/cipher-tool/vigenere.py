def encrypt(original, key):
    encrypted_word = ""
    counter = 0
    for char in original:
        if char.isalpha():
            key_index = counter % len(key)
            shift = ord(key[key_index].upper()) - 65
            if char.isupper():
                new_char = chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                new_char = chr((ord(char) - 97 + shift) % 26 + 97)
            encrypted_word += new_char
            counter += 1
        else:
            encrypted_word += char
    return encrypted_word

def decrypt(original, key):
    decrypted_word = ""
    counter = 0
    for char in original:
        if char.isalpha():
            key_index = counter % len(key)
            shift = ord(key[key_index].upper()) - 65
            if char.isupper():
                new_char = chr((ord(char) - 65 - shift) % 26 + 65)
            else:
                new_char = chr((ord(char) - 97 - shift) % 26 + 97)
            decrypted_word += new_char
            counter += 1
        else:
            decrypted_word += char
    return decrypted_word
