# Practical Web Pentesting Methodology and Burp Suite Introduction

This document outlines a general methodology for conducting web application penetration tests and provides a more detailed introduction to Burp Suite, a popular tool for such assessments.

## 1. Introduction to Practical Web Pentesting

Web application penetration testing is a simulated cyberattack against a web application to check for exploitable vulnerabilities. The primary goal is to identify security weaknesses before malicious actors do.

**Key Objectives:**
*   Identify security vulnerabilities in web applications.
*   Assess the business risk associated with these vulnerabilities.
*   Provide recommendations for remediation.
*   Verify the effectiveness of security controls.

**Ethical Considerations (Crucial Reminder!):**
*   **Explicit Permission:** ALWAYS obtain explicit, written permission from the application owner before conducting any form of testing. Unauthorized testing is illegal.
*   **Scope Definition:** Clearly define and adhere to the scope of the test (e.g., target URLs, types of tests allowed, testing window).
*   **Data Privacy:** Handle any sensitive data encountered with extreme care and in accordance with legal and ethical guidelines.
*   **Minimize Disruption:** Conduct tests in a way that minimizes potential disruption to the application's normal operation, especially in production environments.
*   **Responsible Disclosure:** Report all findings to the application owner in a clear, constructive, and confidential manner.

**Phases of a Web Pentest (General Flow):**
1.  **Planning and Scoping:** Defining objectives, scope, rules of engagement.
2.  **Information Gathering (Reconnaissance):** Collecting information about the target application and its infrastructure.
3.  **Threat Modeling & Vulnerability Analysis:** Identifying potential threats and vulnerabilities based on gathered information and application functionality.
4.  **Exploitation:** Attempting to exploit identified vulnerabilities to confirm their existence and assess impact.
5.  **Post-Exploitation:** Determining the extent of compromise and potential for further access (if applicable and in scope).
6.  **Reporting:** Documenting findings, impact, and remediation recommendations.
7.  **Remediation & Re-testing:** (Often a follow-up phase) Verifying that fixes have been applied correctly.

## 2. Detailed Web Pentesting Phases & Techniques

This expands on the "General Approach to Testing" mentioned previously.

### Phase 1: Information Gathering (Reconnaissance)

The goal is to understand the application's attack surface.

*   **Manual Exploration:**
    *   Browse the entire application as a normal user and with different user roles (if available).
    *   Understand all functionalities: registration, login, profile management, specific business logic features, contact forms, file uploads/downloads, etc.
    *   Identify all user input points: URL parameters (GET), form fields (POST), HTTP headers (cookies, custom headers), file uploads, WebSockets messages.
    *   Examine HTML source code: Look for comments, hidden fields, links to scripts, and clues about frameworks or technologies used.
    *   Analyze JavaScript files: Understand client-side logic, API endpoints being called, data handling.
    *   Map application structure: Note down pages, directories, and how they link together.
*   **Automated & Semi-Automated Techniques:**
    *   **Technology Fingerprinting:** Identify web server software (Apache, Nginx, IIS), backend languages/frameworks (PHP, Java/Spring, Python/Django, Node.js, Ruby on Rails, ASP.NET), CMS (WordPress, Joomla, Drupal), JavaScript libraries (jQuery, React, Angular, Vue). Tools like Wappalyzer (browser extension), WhatWeb.
    *   **Subdomain Enumeration:** Discover related subdomains. Tools: `sublist3r`, `amass`, `findomain`, online services.
    *   **Directory & File Brute-Forcing:** Discover hidden or unlinked files and directories. Tools: `dirb`, `dirbuster`, `gobuster`, `ffuf`. Use common wordlists (e.g., SecLists).
    *   **Port Scanning (on the web server):** Identify open ports and services. Tool: `nmap`. (e.g., `nmap -sV -p- <target_ip>`)
    *   **Search Engine Dorking (Google Hacking):** Use search engines to find indexed information that shouldn't be public (e.g., error messages, specific filetypes, login pages). Example dorks: `site:example.com intitle:"index of"`, `site:example.com filetype:log`, `site:example.com inurl:adminlogin`.
    *   **Analyze `robots.txt` and `sitemap.xml`:** These files can reveal paths intended to be disallowed for crawlers or a map of the site, sometimes pointing to sensitive areas.

### Phase 2: Vulnerability Analysis & Exploitation

This is where you actively test for vulnerabilities.

*   **A. Configuration and Deployment Management Testing:**
    *   Test for default credentials on admin panels, databases, or other services.
    *   Check for exposed configuration files (e.g., `.env`, `web.config`, `config.json`), backup files (`.bak`, `~`), or source code repositories (`.git`, `.svn`).
    *   Verify SSL/TLS configuration strength (e.g., using SSL Labs' SSL Test, `testssl.sh`). Look for weak ciphers, protocol issues, certificate validity.
    *   Check for enabled directory listing on the web server.
    *   Look for unnecessary HTTP methods (e.g., PUT, DELETE, TRACE if not used by the application).

*   **B. Identity Management Testing:**
    *   Test username enumeration (e.g., different responses for valid vs. invalid usernames on login/reset pages).
    *   Assess password policy strength (complexity, length, lockout mechanisms).
    *   Test password reset functionality for flaws (e.g., weak/predictable tokens, token leakage, insecure password change process).
    *   Check for insecure account recovery mechanisms (e.g., easily guessable security questions).

*   **C. Authentication Testing:**
    *   Attempt to bypass authentication mechanisms.
    *   Test for brute-force/credential stuffing vulnerabilities on login forms (check for rate limiting, account lockout).
    *   Ensure credentials are transmitted securely (over HTTPS).
    *   Test for flaws in multi-factor authentication (MFA) implementation if present (e.g., bypasses, weak token generation).
    *   Check for "remember me" functionality and how it's implemented (e.g., long-lived cookies, secure generation).

*   **D. Authorization Testing:**
    *   **Vertical Privilege Escalation:** As a low-privileged user, attempt to access functionalities or resources intended for high-privileged users (e.g., admin pages).
    *   **Horizontal Privilege Escalation:** As an authenticated user, attempt to access resources belonging to other users with similar privilege levels (e.g., viewing another user's profile by changing an ID).
    *   **Insecure Direct Object References (IDOR):** Manipulate user-supplied parameters (e.g., IDs in URLs or request bodies) to access unauthorized data.
    *   Test if access controls are enforced on the server-side and cannot be bypassed by manipulating client-side code.

*   **E. Session Management Testing:**
    *   Analyze session token generation (randomness, length, entropy). Use Burp Sequencer.
    *   Check how session tokens are transmitted (e.g., secure cookies with HttpOnly and Secure flags, avoid URL parameters).
    *   Test session token invalidation on logout, idle timeout, and absolute timeout.
    *   Test for session fixation vulnerabilities (attacker sets victim's session ID).
    *   Check for Concurrent Session Management (e.g. how many active sessions per user are allowed).

*   **F. Input Validation Testing (Testing for specific vulnerabilities like OWASP Top 10):**
    *   **SQL Injection (A03:2021):** Inject SQL metacharacters (`'`, `"`, `;`, `--`, `/* */`) and payloads into all input fields. Use tools like SQLMap for automation after manual detection.
    *   **Cross-Site Scripting (XSS) (A03:2021):** Inject HTML/JavaScript payloads (`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`) into input fields. Test for Stored, Reflected, and DOM-based XSS. Check different contexts (HTML, attributes, JavaScript strings, URLs).
    *   **Command Injection (A03:2021):** Inject OS command metacharacters (`;`, `|`, `&&`, `$( )`, `` ` ``) if input is used in system calls.
    *   **XML External Entity (XXE) (A03:2021):** If XML input is processed, test for XXE by injecting malicious DTDs.
    *   **Server-Side Request Forgery (SSRF) (A10:2021):** If the application fetches resources based on user input, try to make it request internal or arbitrary external URLs.
    *   **Directory Traversal / Path Traversal:** Attempt to access files outside the web root (e.g., `../../etc/passwd`, `..\..\boot.ini`).
    *   **File Inclusion (LFI/RFI):** If input is used in file include statements, try to include local files or remote files.
    *   **HTTP Parameter Pollution (HPP):** Submit multiple instances of the same parameter to see how the application handles it, potentially bypassing validation or causing unexpected behavior.

*   **G. Error Handling Testing:**
    *   Induce errors (e.g., invalid input, unexpected requests) to check if verbose error messages are displayed.
    *   Verbose errors can reveal stack traces, internal paths, SQL queries, or other sensitive information.

*   **H. Cryptography Testing (A02:2021):**
    *   Ensure all sensitive data is encrypted in transit (HTTPS with strong TLS configuration).
    *   If sensitive data is stored, verify if it's encrypted at rest and how (e.g., password hashing using bcrypt, scrypt, Argon2).
    *   Look for weak or custom cryptographic implementations.

*   **I. Business Logic Testing (A04:2021 - Insecure Design):**
    *   This is highly application-specific.
    *   Understand the application's workflows and try to abuse them.
    *   Examples: Manipulating prices in an e-commerce cart, bypassing payment steps, exploiting race conditions, transferring funds beyond limits.

*   **J. Client-Side Testing:**
    *   Analyze client-side JavaScript code for vulnerabilities like DOM-based XSS.
    *   Check for insecure storage of sensitive data in the browser (e.g., localStorage, sessionStorage, cookies without proper flags).
    *   Test for client-side logic that can be bypassed to affect server-side state if not validated server-side.

*   **K. API Testing (if applicable):**
    *   Test APIs for all the above vulnerabilities (Authentication, Authorization, Injection, etc.).
    *   Check for rate limiting, insecure API key handling, mass assignment vulnerabilities.

## 3. Introduction to Burp Suite

Burp Suite is an integrated platform for performing security testing of web applications. Its tools work together seamlessly to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.

**Setting up Burp Suite:**
1.  **Download & Install:** Get Burp Suite (Community Edition is free) from PortSwigger's website.
2.  **Configure Browser Proxy:**
    *   Open Burp Suite. Go to the `Proxy` tab, then the `Options` sub-tab. Note the Proxy Listeners (default is `127.0.0.1:8080`).
    *   Configure your web browser to use this address and port as its HTTP/S proxy. (e.g., Firefox: Settings > Network Settings > Manual proxy configuration).
    *   For HTTPS: You'll need to install Burp's CA certificate in your browser to avoid SSL warnings. In Burp, go to `Proxy` > `Options`, click `Import / export CA certificate`, export it in DER format, and import it into your browser's certificate authorities list (trust it for websites).
3.  **Turn Intercept On/Off:** In Burp's `Proxy` > `Intercept` tab, toggle `Intercept is on/off` to start/stop capturing requests.

**Key Modules Overview (Community Edition Focus):**

*   **Target:**
    *   **Site map:** Provides a hierarchical representation of the application's content, discovered through browsing or spidering.
    *   **Scope:** Define what's in scope for your testing to focus Burp's tools (e.g., only show in-scope items in history, prevent accidental testing of out-of-scope targets).

*   **Proxy:** The core of Burp. It acts as a Man-in-the-Middle (MITM) proxy.
    *   **Intercept:** Allows you to view, modify, forward, or drop individual HTTP/S requests and responses passing between your browser and the target server.
    *   **HTTP history:** Logs all requests and responses. You can view details, sort, filter, and send items to other Burp tools.
    *   **WebSockets history:** Logs WebSocket messages if the application uses them.
    *   **Options:** Configure proxy listeners, SSL passthrough, response modification rules, etc.

*   **Repeater:**
    *   Allows you to manually resend and modify individual HTTP requests multiple times and analyze the responses.
    *   Extremely useful for fine-tuning payloads, testing input validation, and exploring how different inputs affect the response.

*   **Intruder:** (Limited in Community Edition, but still useful)
    *   Automates customized attacks by sending many HTTP requests with modified payloads.
    *   **Positions:** Define where to inject payloads in a base request.
    *   **Payloads:** Configure lists of values to insert (e.g., numbers, strings from a list, brute-force characters).
    *   **Attack Types (Community Edition has "Sniper"):**
        *   *Sniper:* Uses a single payload set, iterating through each position one by one. Good for testing individual parameters.
    *   Useful for fuzzing, brute-forcing credentials (slowly, to avoid lockout), enumerating parameters, or identifying subtle differences in responses.

*   **Decoder:**
    *   A utility for transforming data between common encoding schemes (e.g., URL, HTML, Base64, Hex) and for hashing data.
    *   Useful when crafting payloads or analyzing obfuscated data.

*   **Comparer:**
    *   A utility for performing a visual "diff" between two pieces of data (e.g., two requests, two responses, or any text).
    *   Helpful for identifying subtle differences that might indicate a vulnerability (e.g., different responses to valid vs. invalid input in blind SQLi).

*   **Sequencer:** (Limited in Community Edition)
    *   Analyzes the quality of randomness in session tokens or other supposedly unpredictable data items.
    *   Captures a large number of tokens and performs statistical tests on them.

*   **Scanner:** (Primarily a Burp Suite Professional feature)
    *   Automated vulnerability scanner that crawls content and audits for a wide range of vulnerabilities.

**Basic Burp Suite Workflow Example:**
1.  **Setup:** Configure browser proxy to point to Burp. Install Burp's CA certificate.
2.  **Explore:** Browse the target application normally. Burp will populate the `Target` > `Site map` and `Proxy` > `HTTP history`.
3.  **Define Scope:** Add your target application to the scope in the `Target` tab.
4.  **Analyze Traffic:** Review requests and responses in `HTTP history`. Look for interesting parameters, cookies, headers.
5.  **Manual Testing with Repeater:**
    *   Find an interesting request in `HTTP history` (e.g., a form submission, a request with parameters).
    *   Right-click and "Send to Repeater".
    *   In Repeater, modify parameters, headers, or the request body. Click "Send".
    *   Analyze the response. Repeat with different modifications.
6.  **Automated Testing with Intruder (e.g., Fuzzing a parameter):**
    *   Send a request to Intruder.
    *   Go to the `Intruder` tab, `Positions` sub-tab. Clear default payload markers (`§`) and add markers around the parameter you want to fuzz.
    *   Go to the `Payloads` sub-tab. Select a payload type (e.g., "Simple list") and add your fuzz strings.
    *   Click "Start attack". A new window will show results. Analyze responses for anomalies.
7.  **Use Decoder/Comparer:** As needed to understand data or compare responses.

## 4. Reporting

Effective reporting is crucial for a penetration test to deliver value.

**Key Elements of a Pentest Report:**
*   **Executive Summary:** High-level overview of findings, overall risk posture, and key recommendations for a non-technical audience.
*   **Methodology:** Description of the approach, tools, and scope.
*   **Findings:**
    *   Detailed description of each vulnerability found.
    *   Severity rating (e.g., Critical, High, Medium, Low, Informational) based on impact and exploitability (CVSS can be used).
    *   Evidence of the vulnerability (e.g., screenshots, request/response logs, steps to reproduce).
    *   Potential business impact.
*   **Remediation Recommendations:** Clear, actionable steps to fix each vulnerability.
*   **Conclusion:** Overall assessment and summary.
*   **Appendices (Optional):** Tool outputs, list of tested URLs, etc.

A good report helps developers understand the issues and enables management to prioritize fixes.
