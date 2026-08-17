# Day 01 — Multi-Cipher Encoder/Decoder

## 30 Days. 30 Challenges.

This is Day 01 of the **30 Days of Cyber** community challenge — 30 days, 30 hands-on cybersecurity projects, built from scratch. Each day connects to the ones before it, starting from the basics and climbing toward real offensive/defensive scenarios.

The goal: research, learn, understand, and build. No copy-pasting tutorials — just real problem-solving.

---

## What I Built

A command-line multi-cipher tool that can encode and decode text using four different methods:

- Caesar Cipher
- Base64
- Vigenère Cipher
- Hex

---

## How It Works

Run `python main.py`, pick a cipher, choose encrypt or decrypt, enter your message, and get the result.

---

## The Ciphers Explained

### 1. Caesar Cipher

A substitution cipher where each letter is shifted by a fixed number of positions in the alphabet.

**How it works:**
- Take each letter, find its position (0–25)
- Add the shift value
- Use modulo 26 to wrap around if it goes past Z
- Convert back to a letter

**Formula:** `chr((ord(char) - 65 + shift) % 26 + 65)`

Example: `HELLO` with shift 3 → `KHOOR`

To decrypt, subtract the shift instead of adding it.

---

### 2. Base64

An encoding scheme that converts binary data into a set of 64 printable ASCII characters.

**How it works:**
- Convert each character to its 8-bit binary representation
- Concatenate all bits into one long string
- Split into 6-bit chunks
- Map each 6-bit chunk to the Base64 alphabet (A-Z, a-z, 0-9, +, /)
- Add `=` padding if input length isn't a multiple of 3

**Base64 alphabet:** `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

Example: `hello` → `aGVsbG8=`

To decode, reverse the process — convert each Base64 character back to 6 bits, join them, split into 8-bit groups, convert back to characters.

---

### 3. Vigenère Cipher

A polyalphabetic cipher that uses a keyword to determine different shift values for each letter — essentially multiple Caesar ciphers applied in sequence.

**How it works:**
- Each letter of the keyword provides a different shift (A=0, B=1, ..., Z=25)
- The keyword repeats to match the message length
- Non-alpha characters pass through without consuming a keyword letter

**Formula:** Same as Caesar, but `shift` changes per character based on the keyword.

Example: `helloworld` with key `key` → `rijvsuyvjn`

To decrypt, subtract the keyword shift instead of adding it.

---

### 4. Hex

The simplest encoding — each character is converted to its 2-digit hexadecimal ASCII value.

**How it works:**
- Encode: `ord(char)` → format as 2-digit hex
- Decode: take pairs of hex digits → `int(pair, 16)` → `chr()`

Example: `Hi` → `4869`

---

## Project Structure

```
cipher-tool/
├── main.py           # CLI menu — ties everything together
├── caesar.py         # Caesar cipher encrypt/decrypt functions
├── base64_codec.py   # Base64 encode/decode functions (manual implementation)
├── vigenere.py       # Vigenère cipher encrypt/decrypt functions
├── hex_codec.py      # Hex encode/decode functions
└── README.md         # This file
```

---

## What I Learned

- ASCII values and character manipulation with `ord()` / `chr()`
- Modulo operations for wrapping around the alphabet
- Binary representation and bit manipulation
- How Base64 actually works under the hood
- Polyalphabetic substitution (Vigenère)
- Structuring code with functions and imports
- Building a CLI tool from scratch

---

**#30DaysOfCyber**
