## What it does

This program lets you encrypt and decrypt messages using 7 different cipher techniques:

* **Mixed Alphabet** - Uses a keyword to create a substitution alphabet
* **Caesar Cipher** - Shifts letters by a fixed number
* **Polyalphabetic Caesar** - Caesar cipher with increasing shift
* **Vigenère Cipher** - Uses a keyword with ASCII characters
* **Columnar Transposition** - Rearranges text in columns
* **Rail Fence** - Writes text in zigzag pattern
* **Monoalphabetic** - Random letter substitution

## How to use

1. Run `python ciphercraft.py`
2. Pick a cipher from the menu
3. Choose encrypt or decrypt
4. Enter your key and message
5. Hit process to see the result

## Requirements

* Python 3.x
* Tkinter (comes with Python)

## Key examples

* Caesar: `3` (shift by 3)
* Mixed Alphabet: `SECRET` (keyword)
* Rail Fence: `4` (number of rails)
* Columnar: `HELLO` or `2 4 1 3` (column order)

That's it. Simple crypto tool for learning how these old ciphers work.
