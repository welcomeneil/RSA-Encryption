# Assignment 6 - Public Key Cryptography

The point of this program is to implement RSA encryption, or a form of Public-key, assymetric cryptography. When built, keygen.c should generate two keys, one public and one private. The public key will be sent to a file specified in the command line after a specification to "-i". By default, the program will put the public key in a file named "rsa.pub" if no file is specified. The private key will be sent to a file specified in the command line after a specification to "-i". By default, the program will put the private key in a file named "rsa.priv" if no file is specified. When built, encrypt.c will be able to encrypt a specified file following the command line option "-i", and send the ciphertext to a specified file following the command line option "-o". If no files are specified, then the program will encrypt from stdin and send the ciphertext to stdout. When built, decrypt.c will be able to decrypt a specified file following the command line option "-i", and send the decrypted message to a specified file following the command line option "-o". If no files are specified, then the program will decrypt from stdin and send the message to stdout. Each program has a manual page that can be brought up by specifying the command line option "-h". Each program also has statistics that can be brought up by specifying command line option "-v".

## Building

Build the program with:

```
$ make
```
or
```
$ make all
```
or for solely keygen
```
$ make keygen 
```
or for solely encrypt
```
$ make encrypt
```
or for solely decrypt
```
$ make decrypt
```
## Running

Run the keygen program with:

```
$ ./keygen [-hv] [-b bits] -n pbfile -d pvfile
```
and the encrypt program with:
```
$ ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey
```
and the decrypt program with:
```
$ ./decrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey
```
