# ElGamal Encryption using Baby Jubjub Curve

This project implements the **ElGamal encryption scheme** using the **Baby Jubjub elliptic curve** (BN254) with the help of the Arkworks cryptographic library. The scheme is designed to encrypt and decrypt messages securely using elliptic curve cryptography (ECC).

### Overview of ElGamal Encryption

The **ElGamal encryption** scheme is a public-key encryption system based on the Diffie-Hellman key exchange. It works over elliptic curves to provide secure encryption and decryption. The scheme involves three main steps: **Key Generation**, **Encryption**, and **Decryption**.

- **Key Generation**: 
  - The private key is a randomly selected scalar $(d)$.
  - The public key is computed as $P_{\text{pub}} = d \cdot G$, where $G$ is the base point of the elliptic curve and $d$ is the private key.

- **Encryption**:
  - The message is first mapped to a point on the elliptic curve.
  - A random scalar $r$ is chosen for each encryption to ensure that the ciphertext is different each time.
  - The ciphertext consists of two parts:
    - $C_1 = r \cdot G$, where $r$ is the random scalar and $G$ is the base point of the elliptic curve.
    - $C_2 = M + r \cdot P_{\text{pub}}$, where $M$ is the message and $P_{\text{pub}}$ is the public key.

- **Decryption**:
  - The recipient, who knows the private key $d$, computes $d \cdot C_1$, which is equivalent to $r \cdot P_{\text{pub}}$.
  - The recipient then subtracts this value from $C_2$, recovering the original message.

### Project Description

This project implements the core functions of the ElGamal encryption scheme:

- **Key Generation**: The private key is generated randomly, and the public key is computed by multiplying the base point of the elliptic curve by the private key.
- **Message Encoding**: The message is encoded as a point on the elliptic curve and then encrypted.
- **Encryption**: The plaintext is encrypted using the public key and a randomly chosen scalar $r$.
- **Decryption**: The ciphertext is decrypted using the private key, and the original message is recovered.
- **Rerandomization**: A function is provided to rerandomize the ciphertext, which can add a layer of security by generating a new random value for encryption while keeping the underlying plaintext intact.


