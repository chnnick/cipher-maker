# Cipher Generator

A simple encryption and decryption tool that supports **Vigenère** and **Caesar** ciphers. Works with all printable ASCII characters (codes 32–126).

---

## Features
- **Encrypt or decrypt text**:
  - **Vigenère Cipher**: Key-based encryption using a string.
  - **Caesar Cipher**: Shift-based encryption using an integer.
- Interactive menu-driven interface.
- Input validation for plaintext, ciphertext, and keys.

---

## Example Usage

### Encrypt with Vigenère Cipher:
```bash
./cipher.py encrypt v "Hello World" "Hello World"
```
Will output:
```bash
Encrypted message:
1kyy @O &yi
```

### Encrypt with Caesar Cipher:
```bash
./cipher.py encrypt c "Hello World" 3
```
Will output:
```bash
Encrypted message:
Khoor#Zruog
```

### Decrypt with Vigenère Cipher:
```bash
./cipher.py decrypt v "1kyy @O &yi" "Hello World"
```
Will output:
```bash
Decrypted message:
Hello World
```

### Decrypt with Caesar Cipher:
```bash
./cipher.py decrypt c "Khoor#Zruog" 3
```
Will output:
```bash
Decrypted message:
Hello World
```