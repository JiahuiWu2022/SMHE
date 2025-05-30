# SMHE
Secure multi-key homomorphic encryption with application to privacy-preserving federated learning

The experiments were conducted on a computer equipped with an Nvidia GeForce GTX 1080 Ti GPU and an Intel Core i7-6700 CPU. The SMHE algorithms were implemented in C++ using the NTL 10.4.0 [32] and GMP 6.2.1 [33] libraries to handle arbitrary-length integers and high-precision arithmetic. The FL models were executed using the PyTorch 1.11.0 framework in Python 3.8. To build our PPFL framework, a dynamic library containing all SMHE-related code was generated and invoked within a Python script.

This repository provides only the implementation of the SMHE scheme. The federated learning model used in our experiments can be obtained from https://github.com/vaseline555/Federated-Learning-in-PyTorch.git.
