# A03:2021 - Injection

**What it is:**
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

**Common Types / How it Works:**

*   **SQL Injection (SQLi):**
    *   *How:* Malicious SQL code is inserted into input fields (e.g., search bars, login forms, URL parameters). If the application concatenates this input directly into SQL queries, the database executes the malicious code.
    *   *Example:* Inputting `' OR '1'='1` to bypass authentication.
    *   *Types:* Error-based, Union-based, Blind (Boolean-based, Time-based), Out-of-band.
*   **Cross-Site Scripting (XSS):**
    *   *How:* Malicious client-side scripts (usually JavaScript) are injected into web pages viewed by other users.
    *   *Types:*
        *   **Stored XSS:** Malicious script is stored on the server (e.g., in a database via a comment) and executed when users view the page.
        *   **Reflected XSS:** Malicious script is embedded in a URL or request, reflected off the server, and executed in the victim's browser.
        *   **DOM-based XSS:** Vulnerability in client-side code allows script execution by modifying the Document Object Model.
*   **NoSQL Injection:**
    *   *How:* Similar to SQLi, but targets NoSQL databases (e.g., MongoDB, CouchDB). Attackers inject code or operators specific to the NoSQL database's query language.
*   **OS Command Injection:**
    *   *How:* Attacker injects operating system commands through vulnerable application input (e.g., a form field that is used in a system call).
    *   *Example:* `filename=test.txt; rm -rf /`
*   **LDAP Injection:**
    *   *How:* Exploits applications that construct LDAP (Lightweight Directory Access Protocol) statements from user input, allowing attackers to modify LDAP queries.
*   **XML External Entity (XXE) Injection:**
    *   *How:* An attack against applications that parse XML input. If an XML parser processes external entities from an untrusted source, it can lead to disclosure of confidential data, denial of service, SSRF, etc.
*   **Template Injection:**
    *   *How:* If user input is embedded into a server-side template in an unsafe way, attackers can inject template directives to execute code on the server.

**Potential Impact:**
*   Data theft, modification, or deletion.
*   Denial of service.
*   Complete server takeover or remote code execution.
*   Session hijacking (via XSS).
*   Bypassing authentication.

**Basic Prevention:**
*   **Use Safe APIs (Primary Defense):**
    *   For SQLi: Use Prepared Statements (Parameterized Queries) or Object-Relational Mappers (ORMs) that build queries safely.
    *   Avoid direct use of interpreters where possible.
*   **Server-Side Input Validation:**
    *   Validate input against a strict whitelist of allowed characters, formats, and lengths.
    *   Reject any input that doesn't conform.
*   **Contextual Output Encoding/Escaping:**
    *   For XSS: Encode data before displaying it back to the user, specific to the context (HTML, JavaScript, CSS, URL). Use libraries like OWASP Java Encoder or similar.
    *   For OS Command Injection: Escape shell metacharacters.
*   **Principle of Least Privilege:** Ensure the application's accounts (e.g., database user) have only the minimum necessary permissions.
*   **Content Security Policy (CSP):** For XSS, CSP can restrict the sources from which scripts can be loaded and executed.
*   **Use SAST/DAST tools:** To identify injection flaws during development and testing.