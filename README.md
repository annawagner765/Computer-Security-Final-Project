# T1 Cryptography: Techniques and Practices

This repository hosts the interactive tool developed for the CSE-40567 Computer Security project. The tool is designed to demonstrate the workings of various cryptographic algorithms through an interactive GUI.

## Project Motivation and Background

Cryptography is essential for secure communication. This project focuses on the techniques and practices of cryptographic algorithms, providing an interactive way to explore encryption and decryption methods. The aim is to build a deeper understanding of these algorithms and their efficiencies in data security.

## Implemented Cipher Algorithms

- **Vigenère Cipher**: Implements polyalphabetic substitution using a keyword.
- **Triple DES (3DES)**: An extension of the DES algorithm, used as a standard symmetric algorithm.
- **Advanced Encryption Standard (AES)**: The trusted standard by the U.S. Government for encryption.
- **RSA**: A public-key cryptosystem widely used for secure data transmission.

## Requirements

- **GUI Tool**: The software tool includes a GUI to showcase the encryption and decryption process.
- **Message Types**: Users can encipher texts, images, and binaries (except texts only for Vigenère cipher).
- **Keys**: Users can enter or import keys for encryption/decryption.
- **Exporting**: Encrypted or decrypted messages can be exported or displayed within the GUI.

## Running the Application

To launch the application, navigate to the project's root directory and execute:

```bash
python3 home.py
```

Navigate through the GUI to access different ciphers and their functionalities.

## Test Files and Keys

The repository includes test files and keys for immediate use:

- `test_keys.txt`: Sample keys for each encryption algorithm.
- `sample.txt`: A text file for encryption/decryption tests.
- `sample.png`: An image file for encryption/decryption tests.

## Contact

- Eva Gorzkiewicz - [egorzkie@nd.edu]
- Maya Kuzak - [mkuzak@nd.edu]
- Erin Donaher - [edonaher@nd.edu]
- Anna Wagner - [awagner9@nd.edu]

For any questions or support, please contact one of the team members listed above.
