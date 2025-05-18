# A02:2021 - Cryptographic Failures

**(Previously "Sensitive Data Exposure")**

**What it is:**
Cryptographic Failures occur when sensitive data is not properly protected through encryption and other cryptographic mechanisms, both in transit and at rest. This also includes flaws in the implementation or choice of cryptographic algorithms.

**Common Types / How it Works:**
*   **Data Transmitted in Clear Text:** Sending sensitive data (e.g., credentials, personal information, session tokens) over unencrypted channels like HTTP, FTP, SMTP.
*   **Use of Old or Weak Cryptographic Algorithms/Protocols:** Employing outdated or compromised algorithms (e.g., MD5/SHA1 for hashing passwords, SSLv2/v3, TLS 1.0/1.1, weak ciphers like RC4).
*   **Weak Key Management:**
    *   Using default, weak, or hardcoded cryptographic keys.
    *   Improper key storage and protection.
    *   Not rotating keys regularly.
*   **Sensitive Data Not Encrypted at Rest:** Storing sensitive data (e.g., in databases, file systems) without encryption.
*   **Improper Use of Cryptography:**
    *   Encrypting data but not authenticating it (e.g., not using MACs with symmetric encryption).
    *   Using predictable or static initialization vectors (IVs) for block ciphers.
    *   Error messages leaking cryptographic information (e.g., padding oracle attacks).
*   **Missing or Weak Password Hashing:** Storing passwords in plain text, or using weak, non-salted hashing algorithms.

**Potential Impact:**
*   Data breaches leading to theft of sensitive information (credentials, PII, financial data).
*   Identity theft and fraud.
*   Reputational damage and loss of customer trust.
*   Non-compliance with data protection regulations (e.g., GDPR, PCI DSS).

**Basic Prevention:**
*   **Classify Data:** Identify and classify data processed, stored, or transmitted by the application to determine what needs protection.
*   **Minimize Data Storage:** Don't store sensitive data unnecessarily. If stored, discard it as soon as it's no longer needed or use tokenization/truncation.
*   **Encrypt Data at Rest:** Encrypt all sensitive data stored in databases, files, or backups using strong encryption algorithms and proper key management.
*   **Encrypt Data in Transit:** Use TLS (preferably the latest version, e.g., TLS 1.3) with strong ciphers and forward secrecy for all communication channels. Implement HTTP Strict Transport Security (HSTS).
*   **Use Strong, Modern Algorithms:** Employ up-to-date and robust cryptographic algorithms, protocols, and keys. Follow industry best practices (e.g., NIST guidelines).
*   **Secure Key Management:** Implement a secure key management lifecycle, including generation, storage, rotation, and destruction of keys.
*   **Strong Password Hashing:** Store passwords using strong, adaptive, and salted hashing functions (e.g., Argon2, scrypt, bcrypt).
*   **Disable Caching for Sensitive Data:** Prevent browsers or proxies from caching responses containing sensitive information.