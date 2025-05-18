# A06:2021 - Vulnerable and Outdated Components

**(Previously "Using Components with Known Vulnerabilities")**

**What it is:**
This vulnerability arises when applications use software components (e.g., libraries, frameworks, modules, operating systems) that are outdated, unsupported, or have known security vulnerabilities.

**Common Types / How it Works:**
*   **Unsupported Software:** Using components that are no longer maintained by the vendor, meaning they don't receive security patches (e.g., end-of-life OS, libraries).
*   **Unpatched Vulnerabilities:** Failing to update components even when patches for known vulnerabilities are available.
*   **Lack of Vulnerability Scanning:** Not regularly scanning or monitoring components for known vulnerabilities.
*   **Using Components from Untrusted Sources:** Incorporating components from unofficial or untrusted repositories, which might be malicious or compromised.
*   **Nested Dependencies:** Vulnerabilities can exist in indirect dependencies (libraries used by the libraries your application directly uses).
*   **Client-Side Libraries:** Vulnerable JavaScript libraries running in the user's browser can also lead to exploitation (e.g., XSS).

**Potential Impact:**
*   The impact depends on the specific vulnerability in the component but can range from:
    *   Data leakage or corruption.
    *   Session hijacking.
    *   Denial of service.
    *   Remote code execution and complete server compromise.

**Basic Prevention:**
*   **Inventory Components:** Maintain an inventory of all components used in the application, including their versions and dependencies (both client-side and server-side).
*   **Software Composition Analysis (SCA):** Use SCA tools to identify components and their known vulnerabilities.
*   **Subscribe to Vulnerability Feeds:** Monitor security advisories and vulnerability databases for components used in your application.
*   **Patch Management Process:** Establish a robust patch management process to:
    *   Identify vulnerable components.
    *   Assess the risk of the vulnerability.
    *   Test and apply patches or updates in a timely manner.
    *   If a patch is not available, implement virtual patching or other compensating controls.
*   **Use Official Sources:** Only obtain components from official, trusted sources over secure channels. Verify the integrity of components if possible (e.g., using checksums or digital signatures).
*   **Remove Unused Components:** Regularly remove unused dependencies, unnecessary features, files, and documentation to reduce the attack surface.
*   **Isolate Vulnerable Components:** If a vulnerable component cannot be updated immediately, consider isolating it or applying specific security controls around it.