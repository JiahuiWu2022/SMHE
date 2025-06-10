# SMHE: Secure Multi-Key Homomorphic Encryption Scheme with application to privacy-preserving federated learning

This repository provides the implementation of the Secure Multi-Key Homomorphic Encryption (SMHE) scheme, developed as part of our privacy-preserving federated learning (PPFL) framework.

## Overview

The SMHE scheme was implemented in C++ using the [NTL 10.4.0](https://www.shoup.net/ntl/) and [GMP 6.2.1](https://gmplib.org/) libraries, which support arbitrary-length integers and high-precision arithmetic. For privacy-preserving federated learning tasks, the FL models were implemented in Python 3.8 using the [PyTorch 1.11.0](https://pytorch.org/) framework.

To integrate SMHE into the federated learning setting, a dynamic library was generated from the C++ implementation and invoked via Python scripts.

## Experimental Setup

- **GPU**: Nvidia GeForce GTX 1080 Ti  
- **CPU**: Intel Core i7-6700  
- **C++ Libraries**: NTL 10.4.0, GMP 6.2.1  
- **Python Version**: 3.8  
- **PyTorch Version**: 1.11.0  

## Code Structure

This repository contains:
- The full C++ implementation of the SMHE scheme.
- Example code showing how to compile the dynamic library.
- Integration code for calling the C++ library in Python.

**Note:** This repository provides only the SMHE scheme implementation.  
The federated learning model used in our experiments is available at:  
🔗 [https://github.com/vaseline555/Federated-Learning-in-PyTorch.git](https://github.com/vaseline555/Federated-Learning-in-PyTorch.git)

## How to Use

Instructions for generating the dynamic library and calling it from Python are provided here:  
📘 [CSDN Blog Guide (in Chinese)](https://blog.csdn.net/wujiahui3045/article/details/125220533?spm=1011.2415.3001.5331)

## License

Copyright by Pengcheng Laboratory

## Citation

If you use this code in your research, please cite our paper [add citation or link if applicable].

---

