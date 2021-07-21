An implementation of AES and RSA cryptographic algorithms using Mbed TLS library.

Mbed TLS is a C library that implements cryptographic primitives, X.509 certificate manipulation and the SSL/TLS and DTLS protocols. Its small code footprint makes it suitable for embedded systems.

RSA:

![Alt text](images/rsa_scheme.png?raw=true "Title")

In order to run AES and simplify things, I made a makefile, all you need to do is to open the terminal in the rsa location and type:\
```make``` for creating the ```.exe``` files ( rsa_encrypt, rsa_decrypt, rsa_genkey)\
```make run MSG=TextToEncrypt``` , where the MSG will get the text that will be encrypted.

AES:

![Alt text](images/aes_scheme.png?raw=true "Title")

In order to run AES and simply things, I made a makefile, all you need to do is to open the terminal in the aes location and type:\
```make``` for creating the ```crypt_and_hash.exe```\
In date.txt you need to put the text that you want to encrypt ( it has to be a multiple of 16 bytes)\
```make code``` command will write ( in binary ) the encrypted text in encrypted_data.txt\
```make decode``` command will write the decrypted text in decrypted_data.txt
