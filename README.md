# File Encryptor
Encrypt and decrypt files containing sensitive data.

## Origin
This project came about when I needed to securely encrypt a file.

## How to use
install the cryptography 36.0.0 package from pip using 'pip install cryptography'  
run 'python prog.py' and follow the prompts


## Method and Behaviors
Original file extension will be truncated to 8 characters by default, but this can be modified via the global variable.  
To encrypt a file, the program hashes the password along with a random 16 byte salt and then encrypts the file. It stores the salt at the beginning of the file with the encrypted original file extension and encrypted file data following the salt.  
Decryption hashes the provided password with the salt retrieved from the first 16 bytes of the encrypted file. It then decrypts the original file extension and the file data using the key hash.  
If the password entered is incorrect, the program will prompt the user for the correct password until the valid password is given. This behavior can be changed so that the program exits when provided an incorrect password in order to mitigate brute force attacks.

## Cryptography algorithms
Key hashing uses SHA256 and encryption/decryption uses Fernet. Both are cryptographically secure and part of the cryptography package.

## Dependencies
cryptography 36.0.0 package from pip
