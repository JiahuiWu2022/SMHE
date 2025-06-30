# SMHE: Secure Multi-Key Homomorphic Encryption Scheme with Application to Privacy-Preserving Federated Learning

This repository provides the implementation of the **Secure Multi-Key Homomorphic Encryption (SMHE)** scheme, developed as part of our **Privacy-Preserving Federated Learning (PPFL)** framework.

## 🔍 Overview

The SMHE scheme is implemented in **C++** and integrates seamlessly into federated learning settings via a **Python interface**.

- The encryption scheme is based on the [HEAAN](https://github.com/kimandrik/HEAAN) library, extended to support **multi-key CKKS/BFV encryption**.
- SMHE enables encrypted federated model aggregation across multiple clients holding different keys.
- It is designed for scenarios requiring **strong data privacy**, such as collaborative learning in sensitive domains.

## ⚙️ Implementation Details

- **C++**: Implements core SMHE scheme using:
  - [NTL 10.4.0](https://libntl.org/) — Number Theory Library
  - [GMP 6.2.1](https://gmplib.org/) — GNU Multiple Precision Arithmetic
- **Python 3.8**: Used to run federated learning with:
  - [PyTorch 1.11.0](https://pytorch.org/)
- The SMHE core is compiled as a **shared library (.so/.dll)** and invoked via Python bindings.

## 🧪 Experimental Setup

- **GPU**: Nvidia GeForce GTX 1080 Ti  
- **CPU**: Intel Core i7-6700  
- **Python**: 3.8  
- **PyTorch**: 1.11.0  
- **C++ Dependencies**: NTL 10.4.0, GMP 6.2.1

## 📁 Code Structure

This repository includes:

- 🛠 `MFHE/`: Full C++ implementation of SMHE
- 🔗 `bindings/`: Python interface code for dynamic linking
- 🧪 `examples/`: Sample code for encryption, decryption, and integration into PPFL
- 📄 `README.md`, `LICENSE`: Documentation and license info

> ⚠️ **Note**: This repository provides only the SMHE scheme.  
> The federated learning model used in our experiments is hosted at:  
> 🔗 [https://github.com/vaseline555/Federated-Learning-in-PyTorch.git](https://github.com/vaseline555/Federated-Learning-in-PyTorch.git)

## 🚀 How to Use

Follow the detailed tutorial in our blog (in Chinese):

📘 [CSDN Blog Guide](#) *([Python calls C++](https://blog.csdn.net/wujiahui3045/article/details/125220533?spm=1011.2415.3001.5331))*

1. Compile the dynamic library:
   ```bash
   g++ -shared -fPIC smhe.cpp -o libsmhe.so -lntl -lgmp
2. Use Python’s ctypes or cffi to call SMHE functions from Python scripts.

## License

This project is based on HEAAN, licensed under the Creative Commons Attribution-NonCommercial 3.0 Unported License (CC BY-NC 3.0).

Modifications and extensions in this repository are also released under the same license.

📜 License: http://creativecommons.org/licenses/by-nc/3.0/

© Copyright by Pengcheng Lab.

This repository is for academic and non-commercial research use only.

## Citation

If you use this code in your research, please cite our paper https://arxiv.org/abs/2506.20101.

---

