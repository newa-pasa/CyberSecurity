# Cryptography & Encryption Techniques

**Cryptography** (from Greek "kryptos" meaning hidden, and "graphein" meaning to write) is the science and practice of secure communication in the presence of third parties (called adversaries). It involves techniques for transforming information into an unreadable format (encryption) and then back into its original readable format (decryption).

**Encryption** is the process of converting plaintext (original, readable data) into ciphertext (unreadable, scrambled data) using an algorithm (cipher) and a key.

**Core Goals of Cryptography:**
*   **Confidentiality:** Ensures that data is accessible only to authorized individuals. Achieved through encryption.
*   **Integrity:** Ensures that data has not been altered or tampered with during transmission or storage. Achieved through hashing and message authentication codes (MACs).
*   **Authentication:** Verifies the identity of users, devices, or systems. Achieved through digital signatures, certificates, and passwords.
*   **Non-repudiation:** Provides proof that a specific party sent or received a message, preventing them from denying their actions. Achieved through digital signatures.

**Basic Terminology:**
*   **Plaintext:** The original, unencrypted message or data.
*   **Ciphertext:** The encrypted, unreadable message or data.
*   **Key:** A piece of information (a sequence of numbers or characters) that is used by the cryptographic algorithm to transform plaintext into ciphertext and vice-versa. The security of encrypted data often relies heavily on the secrecy and strength of the key.
*   **Algorithm (Cipher):** The mathematical rules or procedures used for encryption and decryption.

## Symmetric vs. Asymmetric Encryption

Encryption algorithms can be broadly categorized into two main types based on how they use keys: symmetric and asymmetric.

### Symmetric Encryption (Secret Key Cryptography)
*   **Definition:** Uses a single, shared secret key for both the encryption and decryption processes. The sender and receiver must have the same key.
*   **How it Works:**
    1.  Sender uses the shared secret key and a symmetric algorithm (e.g., AES) to encrypt the plaintext into ciphertext.
    2.  Sender transmits the ciphertext to the receiver.
    3.  Receiver uses the *same* shared secret key and the same symmetric algorithm to decrypt the ciphertext back into plaintext.
*   **Analogy:** Think of a locked mailbox where both the sender and receiver use the exact same physical key to lock and unlock it.
*   **Pros:**
    *   **Fast:** Generally much faster and computationally less intensive than asymmetric encryption.
    *   **Efficient for Bulk Data:** Well-suited for encrypting large amounts of data.
*   **Cons:**
    *   **Key Distribution Problem:** Securely sharing the secret key between parties is a major challenge. If the key is intercepted during distribution, the entire communication is compromised.
    *   **Scalability:** Managing unique secret keys for communication between many users can become complex (e.g., for N users, N*(N-1)/2 unique keys are needed for pairwise secure communication).
    *   **No Non-repudiation:** Since both parties have the same key, you can't prove which party created a message if a dispute arises.
*   **Common Algorithms:**
    *   **AES (Advanced Encryption Standard):** Current industry standard, supports key sizes of 128, 192, or 256 bits. Block cipher.
    *   **DES (Data Encryption Standard):** Older standard, 56-bit key, now considered insecure due to its small key size. Block cipher.
    *   **3DES (Triple DES):** Applies DES three times to each data block. More secure than DES but slower than AES. Block cipher.
    *   **RC4 (Rivest Cipher 4):** A stream cipher. Has known vulnerabilities and is generally deprecated for new applications (e.g., in TLS).
    *   **Blowfish, Twofish:** Other strong block ciphers.
*   **Use Cases:**
    *   Encrypting files on a hard drive (Full Disk Encryption).
    *   Securing data in databases.
    *   Encrypting network traffic for session data (e.g., after an initial key exchange using asymmetric methods).

### Asymmetric Encryption (Public-Key Cryptography)
*   **Definition:** Uses a pair of mathematically related keys for encryption and decryption: a **public key** and a **private key**.
    *   **Public Key:** Can be freely distributed to anyone. Used to encrypt data or verify a digital signature.
    *   **Private Key:** Must be kept secret by the owner. Used to decrypt data encrypted with the corresponding public key or to create a digital signature.
*   **How it Works (for Confidentiality):**
    1.  The receiver generates a public-private key pair and shares their public key with the sender.
    2.  Sender uses the receiver's public key and an asymmetric algorithm (e.g., RSA) to encrypt the plaintext.
    3.  Sender transmits the ciphertext to the receiver.
    4.  Receiver uses their *own private key* to decrypt the ciphertext back into plaintext. Data encrypted with a public key can *only* be decrypted by the corresponding private key.
*   **Analogy:** Think of a mailbox with two keys: a public slot (public key) where anyone can drop a message, but only the owner with a unique private key can open the mailbox to retrieve the messages.
*   **Pros:**
    *   **Solves Key Distribution Problem:** The public key can be shared openly without compromising security, as the private key remains secret.
    *   **Enables Digital Signatures:** If a sender encrypts a hash of a message with their private key, anyone with their public key can decrypt it and verify the message's origin and integrity (non-repudiation and authentication).
    *   **Scalability for Key Exchange:** Easier to manage keys in large networks for establishing secure channels.
*   **Cons:**
    *   **Slow:** Significantly slower and more computationally intensive than symmetric encryption.
    *   **Not Ideal for Bulk Data:** Due to its slowness, it's generally not used to encrypt large volumes of data directly.
*   **Common Algorithms:**
    *   **RSA (Rivest-Shamir-Adleman):** Widely used for encryption and digital signatures.
    *   **ECC (Elliptic Curve Cryptography):** Provides similar security to RSA but with smaller key sizes, making it more efficient for mobile and constrained devices.
    *   **Diffie-Hellman Key Exchange:** A protocol used to securely exchange symmetric keys over an insecure channel. It doesn't encrypt data itself but facilitates the sharing of a secret key.
    *   **DSA (Digital Signature Algorithm):** Used for digital signatures.
*   **Use Cases:**
    *   **Secure Key Exchange:** Exchanging symmetric keys (e.g., in TLS/SSL handshakes, PGP).
    *   **Digital Signatures:** Verifying the authenticity and integrity of data and software.
    *   **Public Key Infrastructure (PKI):** Managing digital certificates.
    *   Encrypting small amounts of data, like passwords or symmetric keys.

### Hybrid Encryption
In practice, symmetric and asymmetric encryption are often used together in a **hybrid system** to leverage the strengths of both:
1.  Asymmetric encryption is used to securely exchange a randomly generated symmetric key (session key).
2.  This symmetric key is then used with a fast symmetric algorithm to encrypt the actual bulk data of the communication session.
This approach combines the secure key exchange capability of asymmetric encryption with the speed of symmetric encryption for data transfer. This is how protocols like TLS/SSL (HTTPS) work.

## Hands-on: Encrypting and decrypting files with OpenSSL

**OpenSSL** is a powerful open-source command-line tool and cryptography library. It provides a wide range of cryptographic functions, including generating keys, encrypting/decrypting files, creating digital signatures, managing certificates, and more.

**Prerequisites:**
*   OpenSSL installed on your system (common on Linux and macOS, can be installed on Windows).
*   A terminal or command prompt.

**1. Symmetric Encryption with OpenSSL (e.g., AES-256-CBC)**

   **To encrypt a file:**
   Create a sample plaintext file: `echo "This is a secret message for symmetric encryption." > plaintext_symmetric.txt`

   Command:
   ```bash
   openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in plaintext_symmetric.txt -out ciphertext_symmetric.enc
   ```
   *   `enc`: Specifies that we are using an encryption cipher.
   *   `-aes-256-cbc`: Specifies the AES cipher with a 256-bit key in Cipher Block Chaining (CBC) mode.
   *   `-salt`: Uses a salt to protect against dictionary attacks on the password. The salt is stored in the encrypted file.
   *   `-pbkdf2`: Uses PBKDF2 (Password-Based Key Derivation Function 2) to derive the encryption key from the password. This is more secure than older methods.
   *   `-iter 100000`: Specifies the number of iterations for PBKDF2. A higher number increases security but also slows down the process.
   *   `-in plaintext_symmetric.txt`: Specifies the input file.
   *   `-out ciphertext_symmetric.enc`: Specifies the output (encrypted) file.
   OpenSSL will prompt you to enter and verify an encryption password. **Remember this password!**

   **To decrypt the file:**
   Command:
   ```bash
   openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in ciphertext_symmetric.enc -out decrypted_symmetric.txt
   ```
   *   `-d`: Specifies decryption.
   *   The other options should generally match those used for encryption (cipher, PBKDF2, iter count if specified during encryption and not automatically derived from the file).
   OpenSSL will prompt you for the password you used during encryption.
   Verify the content: `cat decrypted_symmetric.txt`

**2. Asymmetric Encryption with OpenSSL (RSA - for small data or key wrapping)**

   Asymmetric encryption is typically not used to directly encrypt large files due to performance. It's more common for encrypting symmetric keys (key wrapping) or small pieces of data, and for digital signatures.

   **Step 1: Generate an RSA Private Key**
   ```bash
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
   ```
   *   `genpkey`: Command to generate a private key.
   *   `-algorithm RSA`: Specifies the RSA algorithm.
   *   `-out private_key.pem`: Output file for the private key.
   *   `-pkeyopt rsa_keygen_bits:2048`: Sets the key length to 2048 bits (a common secure length).
   (Optional: To encrypt the private key itself with a passphrase: `openssl genpkey -algorithm RSA -aes-256-cbc -out private_key_encrypted.pem -pkeyopt rsa_keygen_bits:2048`)

   **Step 2: Extract the Public Key from the Private Key**
   ```bash
   openssl rsa -pubout -in private_key.pem -out public_key.pem
   ```
   *   `rsa`: Command for RSA key processing.
   *   `-pubout`: Output the public key.
   *   `-in private_key.pem`: Input private key file.
   *   `-out public_key.pem`: Output file for the public key.

   **Step 3: Encrypt a small file/data with the Public Key**
   Create a sample small plaintext file: `echo "Secret data for asymmetric test." > plaintext_asymmetric_small.txt`
   ```bash
   openssl pkeyutl -encrypt -pubin -inkey public_key.pem -in plaintext_asymmetric_small.txt -out ciphertext_asymmetric.dat
   ```
   *   `pkeyutl`: Utility for public key cryptographic operations.
   *   `-encrypt`: Perform encryption.
   *   `-pubin`: Indicates the input key (`-inkey`) is a public key.
   *   `-inkey public_key.pem`: Specifies the public key file.
   *   `-in plaintext_asymmetric_small.txt`: Input data to encrypt.
   *   `-out ciphertext_asymmetric.dat`: Output encrypted data.

   **Step 4: Decrypt the data with the Private Key**
   ```bash
   openssl pkeyutl -decrypt -inkey private_key.pem -in ciphertext_asymmetric.dat -out decrypted_asymmetric_small.txt
   ```
   *   `-decrypt`: Perform decryption.
   *   `-inkey private_key.pem`: Specifies the private key file.
   *   `-in ciphertext_asymmetric.dat`: Input encrypted data.
   *   `-out decrypted_asymmetric_small.txt`: Output decrypted data.
   Verify the content: `cat decrypted_asymmetric_small.txt`

**3. Hashing Files with OpenSSL (for Integrity)**
   Hashing creates a fixed-size string (hash or digest) from input data. It's one-way; you can't get the original data from the hash. If the data changes even slightly, the hash will change significantly.

   Command (e.g., SHA-256):
   ```bash
   openssl dgst -sha256 plaintext_symmetric.txt
   ```
   *   `dgst`: Specifies digest (hashing) functions.
   *   `-sha256`: Specifies the SHA-256 algorithm.
   This will output the SHA-256 hash of the file. You can save this hash and later re-calculate it to verify if the file has been modified.