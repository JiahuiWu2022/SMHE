# SMHE
SMHE is software library that implements secure multi-key homomorphic encryption (SMHE) that supports fixed point arithmetics.
This library supports approximate operations between rational numbers.
The approximate error depends on some parameters and almost same with floating point operation errors.
The scheme in this library is on the paper "Seucre Multi-Key Homomorphic Encryption Scheme with Application to Privacy-Preserving Federated Learning" (https://eprint.iacr.org/2016/421.pdf).

This library does not contain bootstrapping.

This library is written by c++ and using NTL library (http://www.shoup.net/ntl/).

## How to use this library?
### 1. Build a static library/Running test functions
You can make a static library by typing "make all" in the /lib directory. After successful compilation you can find a static library libMFHE.a in the /lib directory.

After you build libMFHE.a, you can run a test program in the /run directory. In run.cpp, you need uncomment tests you need and type "make" in the /run directory. This command will run exe file "MFHE".

We checked the program was working well on Ubuntu 18.04. You need to install NTL (with GMP), pThread, libraries.

## Test
In /run folder, we have test file run.cpp.
You can compile this code using "make".
After that, ./TestMFHE will test SMHE library.
