# Hashing & Steganography

## Cryptographic Hashing

**Definition:** A cryptographic hash function is a mathematical algorithm that takes an input (or 'message') of any size and returns a fixed-size string of characters, which is typically a digest or hash value. The hash value uniquely represents the input data.

**Key Properties of Cryptographic Hash Functions:**
1.  **Deterministic:** The same input will always produce the same hash output.
2.  **One-Way Function (Pre-image Resistance):** It should be computationally infeasible to reverse the process, i.e., to find the original input data given only its hash value.
3.  **Second Pre-image Resistance (Weak Collision Resistance):** Given an input and its hash, it should be computationally infeasible to find a *different* input that produces the same hash.
4.  **Collision Resistance (Strong Collision Resistance):** It should be computationally infeasible to find *any two different* inputs that produce the same hash value.
5.  **Avalanche Effect:** A small change in the input data (e.g., changing a single bit) should produce a drastically different hash output.
6.  **Fixed-Size Output:** The hash function always produces an output of the same length, regardless of the input size.

**Common Uses of Hashing:**
*   **Data Integrity Verification:** To ensure that a file or message has not been altered during transmission or storage. By comparing the hash of the received data with the original hash, any modification can be detected.
*   **Password Storage:** Instead of storing passwords in plaintext, systems store their hash values. When a user tries to log in, the system hashes the entered password and compares it with the stored hash. (Often combined with "salting" to enhance security).
*   **Digital Signatures:** Hashing is a crucial part of creating digital signatures. The message is hashed, and then the hash is encrypted with the sender's private key.
*   **Data Indexing & Deduplication:** Hashing can be used to quickly locate data or identify duplicate data blocks.

## MD5, SHA-256, and their security implications

### MD5 (Message Digest Algorithm 5)
*   **Output Size:** 128 bits (32 hexadecimal characters).
*   **Development:** Designed by Ronald Rivest in 1991.
*   **Security Implications:**
    *   **Collision Vulnerabilities:** MD5 is **cryptographically broken** and unsuitable for most security purposes. Collisions (two different inputs producing the same MD5 hash) can be found relatively easily and quickly using known techniques.
    *   **Not Collision Resistant:** This means attackers can create a malicious file that has the same MD5 hash as a legitimate file, potentially tricking systems that rely on MD5 for integrity checking.
    *   **Not Second Pre-image Resistant (in practice for some scenarios):** While theoretically hard, specific attacks have weakened this property.
    *   **Still used for:** Non-cryptographic checksums (e.g., verifying file downloads where the threat of malicious collision is low), and in some legacy systems (which should be upgraded).
    *   **Recommendation:** **Do not use MD5 for security-critical applications** like digital signatures, password storage (even with salt, stronger hashes are preferred), or SSL certificate generation.

### SHA (Secure Hash Algorithm) Family
The SHA family includes several algorithms. SHA-0 and SHA-1 are older and also have known vulnerabilities. SHA-2 and SHA-3 are the modern, secure standards.

#### SHA-1
*   **Output Size:** 160 bits.
*   **Security Implications:**
    *   **Considered insecure.** Practical collision attacks against SHA-1 have been demonstrated (e.g., the SHAttered attack by Google in 2017).
    *   Major browsers and CAs have deprecated its use for SSL/TLS certificates.
    *   **Recommendation:** Migrate away from SHA-1 to SHA-2 or SHA-3 for all security applications.

#### SHA-2
This is a family of hash functions with different output sizes:
*   **SHA-224** (224 bits)
*   **SHA-256** (256 bits - 64 hexadecimal characters) - Very commonly used.
*   **SHA-384** (384 bits)
*   **SHA-512** (512 bits)
*   **SHA-512/224, SHA-512/256** (truncated versions of SHA-512)

*   **Security Implications (specifically for SHA-256):**
    *   **Currently Considered Secure:** SHA-256 (and other SHA-2 variants) are widely used and considered secure against known cryptographic attacks, including collision attacks.
    *   **Strong Collision Resistance:** No practical collision attacks are known.
    *   **Widely Adopted:** Used in TLS/SSL, digital signatures, blockchain technology (e.g., Bitcoin), password hashing, and various other security protocols.
    *   **Recommendation:** **SHA-256 or higher (SHA-384, SHA-512) are recommended for most new security applications.**

#### SHA-3
*   **Development:** Selected in 2012 after a public competition by NIST. It has a different internal structure (sponge construction) than SHA-1 and SHA-2 (Merkle–Damgård construction).
*   **Output Sizes:** SHA3-224, SHA3-256, SHA3-384, SHA3-512, and variable-length SHAKE128, SHAKE256.
*   **Security Implications:**
    *   **Considered Secure:** Designed to be a secure alternative to SHA-2, not because SHA-2 is broken, but to provide diversity in hashing algorithms.
    *   **Resistant to length extension attacks** by design, unlike SHA-1/SHA-2 if not used carefully (e.g. with HMAC).
    *   **Recommendation:** A strong and secure option, though SHA-2 is still more widely deployed.

**Summary of Security Implications:**
*   Always use hash functions that are currently considered cryptographically secure for security-sensitive applications.
*   Avoid MD5 and SHA-1.
*   SHA-256 (or other SHA-2 variants) and SHA-3 are the current recommended standards.
*   The choice of hash function can impact the overall security of a system. Using a broken or weak hash function can lead to vulnerabilities like data tampering, impersonation, and password compromise.

## Steganography

**Definition:** Steganography is the practice of concealing a secret message, file, image, or video within another, seemingly innocuous file, message, image, or video (the "cover" medium). The goal is to hide the very *existence* of the secret communication.

**Steganography vs. Cryptography:**
*   **Cryptography:** Scrambles a message to make it unreadable (focuses on confidentiality of content). The existence of an encrypted message is usually obvious.
*   **Steganography:** Hides the existence of the message itself. The cover medium appears normal.
*   They can be used together: A message can be encrypted first and then hidden using steganography for an added layer of security.

**Common Steganography Techniques:**
1.  **Least Significant Bit (LSB) Insertion:**
    *   Most common for images and audio files.
    *   The least significant bit(s) of each byte in the cover file are replaced with bits from the secret message.
    *   Changes to LSBs often cause very subtle alterations to the cover medium that are hard for the human eye/ear to detect.
    *   Can be vulnerable to steganalysis if too many LSBs are altered or if patterns emerge.
2.  **Metadata (EXIF Data):**
    *   Many file formats (especially images like JPEG) contain metadata (e.g., camera model, date taken, GPS coordinates).
    *   Secret messages can be hidden within these metadata fields.
3.  **File Slack Space:** Unused space at the end of a file cluster on a disk can be used to hide data.
4.  **Alternate Data Streams (ADS - Windows NTFS):** Allows files to be associated with more than one data stream. Hidden data can be stored in an alternate stream not visible through normal directory listings.
5.  **Network Steganography:** Hiding data in network protocols (e.g., in unused header fields, or by manipulating timing of packets).
6.  **Text Steganography:** Using subtle changes in text formatting, specific word choices, or invisible characters.

## Hands-on: Hiding messages inside images & files

**Tools for Steganography:**
*   **Steghide:** A popular command-line tool for Linux and Windows. Embeds data in various image (JPEG, BMP, WAV, AU) and audio file formats.
*   **OpenStego:** A free, open-source steganography tool with a GUI.
*   **OurSecret, QuickStego:** Other tools with varying features.
*   Online steganography tools (use with caution for sensitive data).

**Conceptual Steps using `steghide` (Command-Line Example):**

1.  **Installation (Linux):**
    ```bash
    sudo apt update
    sudo apt install steghide
    ```

2.  **Prepare Files:**
    *   **Cover File:** An image (e.g., `cover_image.jpg`).
    *   **Secret File:** A text file containing the message to hide (e.g., `secret_message.txt`).
      ```bash
      echo "This is a top-secret message!" > secret_message.txt
      # (Ensure you have a cover_image.jpg in the same directory)
      ```

3.  **Embed the Secret File into the Cover File:**
    ```bash
    steghide embed -cf cover_image.jpg -ef secret_message.txt -sf stego_image.jpg -p mysecretpassword
    ```
    *   `-cf cover_image.jpg`: Specifies the cover file.
    *   `-ef secret_message.txt`: Specifies the file to embed.
    *   `-sf stego_image.jpg`: Specifies the output steganographic file.
    *   `-p mysecretpassword`: (Optional but recommended) Sets a passphrase to encrypt the embedded data. Steghide will prompt if not provided.

4.  **Extract the Secret File from the Steganographic File:**
    ```bash
    steghide extract -sf stego_image.jpg -xf extracted_secret.txt -p mysecretpassword
    ```
    *   `-sf stego_image.jpg`: Specifies the steganographic file.
    *   `-xf extracted_secret.txt`: Specifies the name for the extracted secret file.
    *   `-p mysecretpassword`: Prompts for the passphrase used during embedding.

5.  **Verify:**
    ```bash
    cat extracted_secret.txt
    ```
    This should display "This is a top-secret message!".

**Security Implications & Detection (Steganalysis):**
*   **Not Foolproof:** While steganography aims to hide data, specialized techniques and tools (steganalysis) can be used to detect the presence of hidden information.
*   **Detection Methods:** Statistical analysis of pixel values, frequency domain analysis, visual inspection for anomalies, checking file sizes against typical sizes for the format.
*   **Effectiveness:** Depends on the technique used, the amount of data hidden relative to the cover file size, and the type of cover medium. Hiding large amounts of data is more likely to be detectable.
*   **Malicious Uses:**
    *   **Data Exfiltration:** Employees or attackers can use steganography to sneak sensitive data out of a network.
    *   **Malware Delivery:** Hiding malicious payloads within seemingly harmless files.
    *   **Covert Communication:** Used by criminals or spies to communicate without detection.

**Ethical Considerations:**
*   Like many security tools, steganography can be used for both legitimate (e.g., protecting sensitive information, watermarking) and malicious purposes. Understanding its capabilities is important for both offense and defense.