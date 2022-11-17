# RSA Public-Key Encryption and Signature Lab Solutions

Solution created by [abergie5b/RSAImpl](https://github.com/abergie5b/RSAImpl).

## Compiling on Linux

First, make sure you have the OpenSSL Dev package `libssl-dev` installed. This could vary per distro.

Run the following gcc command to compile:
```
gcc -o lab.o lab.c utils.c -lcrypto
```

Run the binary `lab.o` to get results.
