import caesar
import base64_codec
import vigenere
import hex_codec

print()
print("MULTI-CIPHER TOOL")
print()
print("1. Caesar Cipher")
print("2. Base64")
print("3. Vigenere Cipher")
print("4. Hex")

choice = input("Pick a cipher (1-4): ")

if choice not in ["1", "2", "3", "4"]:
    print("Invalid choice")
else:
    mode = input("e for encrypt, d for decrypt: ").lower()
    message = input("Enter your message: ")

    if choice == "1":
        shift = int(input("Enter shift value: "))
        if mode == "e":
            result = caesar.encrypt(message, shift)
        else:
            result = caesar.decrypt(message, shift)

    elif choice == "2":
        if mode == "e":
            result = base64_codec.encrypt(message)
        else:
            result = base64_codec.decrypt(message)

    elif choice == "3":
        key = input("Enter keyword: ")
        if mode == "e":
            result = vigenere.encrypt(message, key)
        else:
            result = vigenere.decrypt(message, key)

    elif choice == "4":
        if mode == "e":
            result = hex_codec.encrypt(message)
        else:
            result = hex_codec.decrypt(message)

    print("Result:", result)
