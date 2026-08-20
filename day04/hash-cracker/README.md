# Day 04 — Hash Cracker

## What I Built

A hash cracking tool with four attack modes: dictionary, brute-force, rule-based mutations, and multiprocess dictionary. Supports MD5, SHA1, SHA256, and SHA512 with auto-detection.

---

## How It Works

```
python cracker.py
```

Pick an attack mode, enter the hash you want to crack, and the tool attempts to recover the original password.

---

## Attack Modes

### 1. Dictionary Attack
Reads a wordlist file line by line, hashes each word, and compares to the target. Fast and effective for common passwords.

### 2. Brute-Force Attack
Generates every possible character combination up to a max length. Guaranteed to find the password eventually, but exponentially slower with longer passwords and bigger character sets.

### 3. Dictionary + Rules (Mutations)
Takes each word from the wordlist and tries smart variations:
- `password` → `Password` (capitalize)
- `password` → `PASSWORD` (all upper)
- `password` → `drowssap` (reversed)
- `password` → `password0` ... `password9` (digit append)
- `password` → `p@$$w0rd` (leet speak)

Catches people who think small modifications make passwords secure.

### 4. Dictionary (Multiprocess)
Splits the wordlist across all CPU cores and cracks in parallel. Faster for large wordlists when the password is deep in the list.

---

## Features

- **Auto-detection:** Determines hash type from length (MD5=32, SHA1=40, SHA256=64, SHA512=128)
- **Speed counter:** Shows hashes/second and total attempts
- **Configurable charset:** Choose lowercase, digits, uppercase, or all characters for brute-force
- **Large wordlist support:** Handles `rockyou.txt` (14M passwords) with latin-1 encoding

---

## What I Learned

### Hashing
- Hash functions are one-way — you can't reverse them, only guess and compare
- Same input always produces the same output (deterministic)
- MD5 and SHA1 are broken for security but good for learning
- `hashlib` is Python's built-in library for hashing

### Attack Methods
- **Dictionary:** Fast but limited to what's in the wordlist
- **Brute-force:** Complete but exponentially slow (26^4 = 456K combos for 4 lowercase chars)
- **Rules:** Smart middle ground — catches predictable human behavior
- **More cores ≠ always faster:** Process spawning has overhead; for easy targets, simple sequential wins

### Multiprocessing vs Threading
- Threading (port scanner): good for I/O-bound tasks (waiting for network)
- Multiprocessing (hash cracker): good for CPU-bound tasks (doing calculations)
- Python's GIL prevents true parallel threading for CPU work
- Multiprocessing spawns separate processes on different CPU cores
- Tradeoff: startup overhead vs parallel speed gain

### Key Python Concepts
- `itertools.product` — generates all character combinations
- `multiprocessing.Process` — creates parallel workers
- `multiprocessing.Value` — shared state between processes
- `multiprocessing.Manager` — shared data structures
- `if __name__ == "__main__"` — required for multiprocessing on Windows
- `encoding='latin-1'` — handles files with non-standard characters

---

## Demo Hashes to Test

| Hash | Type | Password |
|------|------|----------|
| `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 | password |
| `9fd8301ac24fb88e65d9d7cd1dd1b1ec` | MD5 | butterfly |
| `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | SHA1 | password |
| `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | SHA256 | password |

---

## Project Structure

```
hash-cracker/
├── cracker.py     # The cracking tool (4 attack modes)
├── wordlist.txt   # Small test wordlist
└── README.md      # This file
```

---

## Requirements

- Python 3
- A wordlist (e.g., `rockyou.txt` for real testing)

---

**#30DaysOfCyber**
