import string

MIN = 32
MAX = 126
KEY_RANGE = MAX - MIN + 1

def vigenere_encrypt(plaintext, key):
  ciphertext = ""
  key_len = len(key)
  for i, char in enumerate(plaintext):
    if not (MIN <= ord(char) <= MAX) or not (MIN <= ord(key[i % key_len]) <= MAX):
      raise ValueError("Invalid key or plaintext")
    shift = ord(key[i % key_len]) % KEY_RANGE
    possible_shift = ord(char) + shift
    if possible_shift > MAX:
      possible_shift = (MIN - 1) + (possible_shift - MAX)
    ciphertext += chr(possible_shift)
  return ciphertext

def vigenere_decrypt(ciphertext, key):
  plaintext = ""
  key_len = len(key)
  for i, char in enumerate(ciphertext):
    if not (MIN <= ord(char) <= MAX) or not (MIN <= ord(key[i % key_len]) <= MAX):
      raise ValueError("Invalid key or ciphertext")
    shift = ord(key[i % key_len]) % KEY_RANGE
    possible_shift = ord(char) - shift
    if possible_shift < MIN:
      possible_shift = MAX + 1 - (MIN - possible_shift)
    plaintext += chr(possible_shift)
  return plaintext

def caesar_encrypt(plaintext, key):
  if not isinstance(key, int):
    raise ValueError("Invalid key: Not an integer")
  shift = key % KEY_RANGE
  original = ''.join(chr(i) for i in range(MIN, MAX + 1))
  shifted = original[shift:] + original[:shift]
  cipher = str.maketrans(original, shifted)
  return plaintext.translate(cipher)

def caesar_decrypt(ciphertext, key):
  if not isinstance(key, int):
    raise ValueError("Invalid key: Not an integer")
  shift = key % KEY_RANGE
  original = ''.join(chr(i) for i in range(MIN, MAX + 1))
  shifted = original[-shift:] + original[:-shift]
  cipher = str.maketrans(original, shifted)
  return ciphertext.translate(cipher)

def encrypt(cipher_type):
  plaintext = input("Enter the plaintext: ")
  key = input("Enter the key (integer for Caesar): ")
  try:
    if cipher_type == "v":
      ciphertext = vigenere_encrypt(plaintext, key)
    elif cipher_type == "c":
      ciphertext = caesar_encrypt(plaintext, int(key))
    print(f"Encrypted message:\n{ciphertext}")
  except ValueError as e:
    print(f"Error: {e}")

def decrypt(cipher_type):
  ciphertext = input("Enter the ciphertext: ")
  key = input("Enter the key (integer for Caesar): ")
  try:
    if cipher_type == "v":
      plaintext = vigenere_decrypt(ciphertext, key)
    elif cipher_type == "c":
      plaintext = caesar_decrypt(ciphertext, int(key))
    print(f"Decrypted message:\n{plaintext}")
  except ValueError as e:
    print(f"Error: {e}")

def cryptanalysis_caesar(ciphertext):
    print("\n=== Caesar Cipher Cryptanalysis ===")
    for key in range(KEY_RANGE):
        try:
            decrypted = caesar_decrypt(ciphertext, key)
            print(f"Key {key:2d}: {decrypted[:50]}{'...' if len(decrypted) > 50 else ''}")
        except:
            continue
    print("=" * 40)

def main():
    print("Welcome to Nick's Ciphermaker!")
    while True:
      mode = input("Choose mode: (e)ncrypt, (d)ecrypt, (a)nalyze Caesar, or (q)uit: ").lower()
      if mode == "q":
          print("Goodbye!")
          break
      elif mode == "a":
          ciphertext = input("Enter Caesar ciphertext to analyze: ")
          cryptanalysis_caesar(ciphertext)
      elif mode in ["e", "d"]:
    elif mode in ["e", "d"]:
      cipher = input("Choose cipher: (v)Vigenère or (c)Caesar: ").lower()
      if cipher == "v":
        if mode == "e":
            encrypt("v")
        else:
            decrypt("v")
      elif cipher == "c":
        if mode == "e":
            encrypt("c")
        else:
            decrypt("c")
      else:
        print("Invalid cipher choice!")
    else:
      print("Invalid mode choice!")

if __name__ == "__main__":
    main()
