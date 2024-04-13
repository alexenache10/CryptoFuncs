# CryptoFuncs
C++ implementation using OpenSSL for multiple cryptographic functionalities. To run the project, you need to set the OpenSSL library in the Visual Studio project settings.

Implemented Features:
1. Hex String Converter:
Functionality to convert between a hexadecimal string and a binary sequence, facilitating the display of octets in a readable format.

2. ASN.1 Structure for Master Key:
Creation of an ASN.1 structure containing a Master Key with details such as CommonName, Subject, and an Embedded Key, following the provided specifications.
Capability of operating with BIGNUMs.

3. AES-OFB Custom Encryption/Decryption:
Implementation of a customized variant of the OFB mode for AES algorithm, supporting variable key lengths and transmitting the IV as an argument.

4. Key Exchange Simulation:
Simulation of a key exchange between three actors (Alice, Bob, and Charlie) by transmitting encrypted messages encapsulated in ASN1 packets (encoded in DER) according to the specified structure, including support for encryption with AES-256-GCM and ChaCha20_Poly1305.

5. Custom Keystream Generation:
Implementation of a proprietary algorithm for generating a symmetric stream cipher, comprising operations such as byte-state generation, shifting, XOR operations, confusion, and diffusion.
