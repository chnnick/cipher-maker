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
```
Plaintext: Hello, World!
Key: KEY
Ciphertext: Riodc+%bwe|i%
```

### Encrypt with Caesar Cipher:
```
Plaintext: Hello, World!
Key: 5
Ciphertext: Mjqqt%\twqi&
```

### Decrypt with Vigenère Cipher:
```
Ciphertext: Riodc+%bwe|i%
Key: KEY
Plaintext: Hello, World!
```

### Decrypt with Caesar Cipher:
```
Ciphertext: Mjqqt%\twqi&
Key: 5
Plaintext: Hello, World!
```
