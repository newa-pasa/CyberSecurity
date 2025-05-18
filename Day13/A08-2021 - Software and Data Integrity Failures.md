# A08:2021 - Software and Data Integrity Failures

**What it is:**
This category relates to failures in verifying the integrity of software, critical data, and CI/CD pipelines, leading to unauthorized modifications, malicious code execution, or system compromise. It includes issues like insecure deserialization and relying on software updates or plugins from untrusted sources without proper validation.

**Common Types / How it Works:**
*   **Insecure Deserialization:**
    *   *How:* Applications deserialize data (converting a byte stream back into an object) from untrusted sources (e.g., user input, cookies, network traffic). If the deserialization process can be manipulated to create unexpected object types or execute code, it can lead to remote code execution or other attacks.
    *   *Example:* An attacker crafts a malicious serialized object that, when deserialized by the application, executes arbitrary commands on the server.
*   **Compromised CI/CD Pipeline:** Attackers gain access to the continuous integration/continuous deployment pipeline and inject malicious code or configurations into the build or deployment process.
*   **Insecure Auto-Update Functionality:**
    *   Software updates fetched over unencrypted channels (HTTP instead of HTTPS).
    *   Updates downloaded without verifying their digital signature, allowing an attacker to provide a malicious update.
*   **Relying on Unverified Third-Party Components:** Using plugins, libraries, or modules from untrusted sources, repositories, or CDNs without verifying their integrity (e.g., via checksums or signatures). This can lead to the inclusion of malicious or backdoored components.
*   **Data Tampering:** Lack of integrity checks on critical data, allowing attackers to modify it undetected (e.g., modifying data in transit or at rest).

**Potential Impact:**
*   Remote code execution.
*   Data tampering or destruction.
*   System compromise.
*   Installation of malware or backdoors.
*   Denial of service.

**Basic Prevention:**
*   **Verify Software and Data Integrity:**
    *   Use digital signatures or similar mechanisms to verify that software, updates, and critical data are from the expected source and have not been altered.
    *   Validate checksums of downloaded components.
*   **Secure CI/CD Pipelines:**
    *   Implement strong access controls and segregation of duties within the CI/CD pipeline.
    *   Scan code and configurations for vulnerabilities.
    *   Sign and verify build artifacts.
*   **Safe Deserialization Practices:**
    *   Avoid deserializing data from untrusted sources if possible.
    *   If deserialization is necessary, use safe deserialization methods that only allow expected data types.
    *   Implement integrity checks (e.g., digital signatures) on serialized data before deserialization.
    *   Run deserialization code in a low-privilege environment.
*   **Secure Auto-Updates:** Ensure software updates are fetched over secure channels (HTTPS) and their integrity is verified (e.g., via digital signatures) before installation.
*   **Use Trusted Repositories:** Obtain libraries and dependencies from official and trusted repositories. Use SCA tools to monitor for compromised components.
*   **Implement Data Integrity Controls:** Use checksums, MACs (Message Authentication Codes), or digital signatures to protect the integrity of critical data both in transit and at rest.