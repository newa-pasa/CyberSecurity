# Web Application Security Basics

Web Application Security focuses on protecting websites, web applications, and web services from security threats that exploit vulnerabilities in an application's code or architecture. As web applications handle increasingly sensitive data and perform critical functions, their security is paramount.

**Why is Web Application Security Important?**
*   **Data Protection:** To prevent unauthorized access, theft, or modification of sensitive data (e.g., user credentials, personal information, financial details).
*   **Maintaining Trust:** Security breaches erode user trust and can damage an organization's reputation.
*   **Business Continuity:** Attacks can disrupt services, leading to financial losses and operational downtime.
*   **Compliance:** Many regulations (e.g., GDPR, PCI-DSS) require specific security measures for web applications.

**Common Components of a Web Application:**
*   **Client-Side (Frontend):** Code that runs in the user's browser (HTML, CSS, JavaScript). Vulnerabilities here can lead to issues like Cross-Site Scripting (XSS).
*   **Server-Side (Backend):** Code that runs on the web server (e.g., Python, Java, PHP, Node.js). This is where business logic is processed, and databases are accessed. Vulnerabilities here can be severe (e.g., SQL Injection, Remote Code Execution).
*   **Database:** Stores application data. Often a target for attackers seeking to exfiltrate or manipulate information.
*   **Web Server:** Software that serves web content (e.g., Apache, Nginx). Misconfigurations can lead to vulnerabilities.
*   **APIs (Application Programming Interfaces):** Allow different software components to communicate. Insecure APIs can be a major attack vector.

**General Security Principles:**
*   **Input Validation:** Never trust user input. Validate and sanitize all data received from users or external sources on the server-side to prevent injection attacks.
*   **Output Encoding:** Encode data before displaying it back to the user to prevent XSS attacks.
*   **Secure Authentication & Authorization:** Implement strong password policies, multi-factor authentication (MFA), and ensure users only have access to resources they are permitted to see/use (Principle of Least Privilege).
*   **Session Management:** Securely manage user sessions using strong, randomly generated session tokens, and ensure they are properly invalidated upon logout or timeout.
*   **Secure Communication:** Use HTTPS (HTTP Secure) with TLS/SSL to encrypt data in transit between the client and server.
*   **Error Handling:** Implement proper error handling that doesn't reveal sensitive system information to attackers.
*   **Regular Patching & Updates:** Keep all components (server software, libraries, frameworks) up-to-date to protect against known vulnerabilities.
*   **Security Headers:** Utilize HTTP security headers (e.g., Content Security Policy, X-Content-Type-Options, X-Frame-Options) to instruct browsers on how to handle content securely.

## OWASP Top 10 Vulnerabilities

The **OWASP (Open Web Application Security Project)** Top 10 is a widely recognized, regularly updated report outlining the most critical security risks to web applications. While the specific list evolves, it provides excellent guidance on areas to focus on. We'll look at three common examples:

**1. SQL Injection (SQLi)**
*   **What it is:** A vulnerability that allows an attacker to interfere with the queries that an application makes to its database. Attackers can often view data they are not normally able to retrieve, modify or delete data, or even gain administrative control over the database server.
*   **How it works (Simplified):** An attacker inserts malicious SQL code into an input field (e.g., a search box, login form). If the application directly embeds this input into an SQL query without proper sanitization, the malicious code gets executed by the database.
    *   Example: If a query is `SELECT * FROM users WHERE username = '` + userInput + `';`
    *   An attacker might input: `' OR '1'='1`
    *   Resulting query: `SELECT * FROM users WHERE username = '' OR '1'='1';` (which could bypass authentication or dump all users).
*   **Potential Impact:** Data theft, data loss, data corruption, denial of service, complete server takeover.
*   **Basic Prevention:**
    *   **Use Prepared Statements (Parameterized Queries):** This is the most effective method. The SQL query structure is defined first, and then user input is supplied as parameters, ensuring it's treated as data, not executable code.
    *   **Input Validation:** Validate input against expected formats and lengths.
    *   **Least Privilege:** Ensure the application's database account has only the minimum necessary permissions.

**2. Cross-Site Scripting (XSS)**
*   **What it is:** A vulnerability that allows attackers to inject malicious client-side scripts (usually JavaScript) into web pages viewed by other users.
*   **Types:**
    *   **Stored XSS:** The malicious script is permanently stored on the target server (e.g., in a database, via a comment field). When a user views the affected page, the script executes.
    *   **Reflected XSS:** The malicious script is embedded in a URL or other request data. When a user clicks a crafted link or submits a form, the injected script is reflected off the web server to the user's browser.
    *   **DOM-based XSS:** The vulnerability exists in the client-side code itself. The script is executed as a result of modifying the Document Object Model (DOM) environment in the victim's browser.
*   **How it works (Simplified - Reflected):** An attacker crafts a URL like `http://example.com/search?query=<script>alert('XSS')</script>`. If the search page directly displays the `query` parameter without encoding, the script will execute in the browser of anyone clicking that link.
*   **Potential Impact:** Stealing session cookies (session hijacking), defacing websites, redirecting users to malicious sites, capturing keystrokes, performing actions on behalf of the user.
*   **Basic Prevention:**
    *   **Output Encoding:** Encode data before it's displayed on a web page, specific to the context where it's being inserted (e.g., HTML entity encoding for HTML content, JavaScript encoding for script contexts).
    *   **Content Security Policy (CSP):** A powerful browser mechanism to control which resources (scripts, images, etc.) can be loaded and executed.
    *   **Input Validation:** While not the primary defense for XSS, it can help reduce attack surface.
    *   **Use modern web frameworks:** Many frameworks have built-in XSS protection.

**3. Cross-Site Request Forgery (CSRF)**
*   **What it is:** An attack that tricks a victim's browser into making an unintended, malicious request to a web application where the victim is already authenticated. The application trusts the request because it comes from the victim's browser (with their session cookies).
*   **How it works (Simplified):**
    1.  A user logs into a vulnerable web application (e.g., `bank.com`).
    2.  The user then visits a malicious website (e.g., `evil.com`) in another tab or window.
    3.  `evil.com` might contain hidden code (e.g., an image tag or a form that auto-submits) that makes a request to `bank.com` to perform an action, like transferring funds: `<img src="http://bank.com/transfer?to=attacker&amount=1000" style="display:none;">`.
    4.  Because the user is authenticated with `bank.com`, their browser automatically includes their session cookies with the request, and `bank.com` processes the malicious request as if the user initiated it.
*   **Potential Impact:** Unauthorized fund transfers, changing account details (email, password), making purchases, or any other state-changing action the user is authorized to perform.
*   **Basic Prevention:**
    *   **Anti-CSRF Tokens (Synchronizer Token Pattern):** The most common defense. The server generates a unique, unpredictable token for each user session and embeds it in hidden fields in forms. When a request is submitted, the server checks if the token matches. Attackers cannot guess this token for a victim's session.
    *   **SameSite Cookie Attribute:** Instructs browsers when to send cookies with cross-site requests. `SameSite=Lax` or `SameSite=Strict` can significantly mitigate CSRF.
    *   **Checking Referer/Origin Headers:** Can be used as a supplementary defense, but can sometimes be spoofed or absent.
    *   **Requiring Re-authentication for Sensitive Actions:** Forcing users to re-enter their password before performing critical operations.

## Hands-on: Testing a demo website for vulnerabilities

Testing web applications for vulnerabilities requires a methodical approach and the right tools. **Always ensure you have explicit permission before testing any website that you do not own.** For practice, use intentionally vulnerable applications.

**Intentionally Vulnerable Demo Websites for Practice:**
*   **OWASP Juice Shop:** A modern and sophisticated insecure web application. (Often recommended)
*   **Damn Vulnerable Web Application (DVWA):** A PHP/MySQL web application that is damn vulnerable. Good for beginners. 
*   **WebGoat:** An OWASP project, a deliberately insecure application. 
*   **bWAPP (buggy Web Application):** Another intentionally vulnerable web application. 
*   **Mutillidae II:** An OWASP Flagship Project, deliberately vulnerable web application. 

**Common Tools:**
*   **Web Browser Developer Tools:** (Built into Chrome, Firefox, Edge, etc.) Essential for inspecting HTML, CSS, JavaScript, network requests, cookies, and local storage.
*   **Burp Suite:** (Community Edition is free) An integrated platform for web application security testing. Its proxy feature allows you to intercept, inspect, and modify all HTTP/S traffic between your browser and the target application. It also includes tools for scanning, fuzzing, and more.
*   **OWASP ZAP (Zed Attack Proxy):** A free, open-source alternative to Burp Suite.
*   **Nmap:** For network discovery and port scanning of the web server.
*   **SQLMap:** An automated SQL injection and database takeover tool.
*   **Various browser extensions:** For security testing.

**General Approach to Testing:**

1.  **Reconnaissance & Information Gathering (Manual Exploration):**
    *   Browse the entire application like a normal user. Understand its functionality, features, and user roles.
    *   Identify all input points: URL parameters, form fields, HTTP headers, cookies, file uploads.
    *   Look at HTML source code, JavaScript files, and comments for clues about how the application works or potential hidden information.
    *   Map out the application structure.

2.  **Configuration and Deployment Management Testing:**
    *   Check for default credentials in admin interfaces.
    *   Look for exposed configuration files or backup files.
    *   Test SSL/TLS configuration (e.g., using SSL Labs).

3.  **Identity Management Testing:**
    *   Test for weak username/password policies.
    *   Check for username enumeration.
    *   Test password reset functionality for flaws.

4.  **Authentication Testing:**
    *   Attempt to bypass authentication.
    *   Test for brute-force vulnerabilities on login forms.
    *   Check if credentials are transmitted securely.

5.  **Authorization Testing:**
    *   Once authenticated, try to access resources or perform actions intended for other users or higher-privileged roles (privilege escalation).
    *   Test for Insecure Direct Object References (IDOR) – e.g., changing an ID in a URL to access another user's data.

6.  **Session Management Testing:**
    *   Check how session tokens are generated, transmitted, and protected.
    *   Test for session fixation vulnerabilities.
    *   Ensure sessions are properly invalidated on logout and timeout.

7.  **Input Validation Testing (Testing for specific vulnerabilities):**
    *   **SQL Injection:**
        *   Try injecting SQL special characters (e.g., `'`, `"`, `;`, `--`) into input fields.
        *   Use basic SQLi payloads like `' OR '1'='1`.
        *   Observe error messages or changes in application behavior.
    *   **Cross-Site Scripting (XSS):**
        *   Inject simple HTML tags (e.g., `<h1>test</h1>`) to see if they are rendered.
        *   Try basic JavaScript payloads (e.g., `<script>alert('XSS')</script>`) in input fields and URL parameters.
        *   Check if the input is reflected on the page or stored and displayed later.
    *   **Command Injection:** Try injecting OS commands.
    *   **Directory Traversal:** Try to access files outside the web root (e.g., `../../../../etc/passwd`).

8.  **Error Handling Testing:**
    *   Induce errors to see if detailed system information or stack traces are revealed.

9.  **Cryptography Testing:**
    *   Check if sensitive data is encrypted in transit (HTTPS) and at rest.
    *   Assess the strength of encryption algorithms used.

10. **Business Logic Testing:**
    *   Look for flaws in the application's workflows that could be abused (e.g., manipulating prices in an e-commerce site).

11. **Client-Side Testing:**
    *   Analyze JavaScript code for vulnerabilities (e.g., DOM XSS, insecure handling of sensitive data).

**Using Burp Suite (Basic Workflow):**
1.  Configure your browser to use Burp Suite as a proxy.
2.  Browse the target application. Burp will capture all requests and responses.
3.  Use the "Target" tab to see the site map.
4.  Use the "Proxy" > "HTTP history" tab to review individual requests/responses.
5.  Right-click a request and send it to "Repeater" to modify and resend it manually.
6.  Send requests to "Intruder" to automate fuzzing or brute-force attacks (with caution and on appropriate targets).

**Ethical Considerations:**
*   **NEVER** test a website without explicit, written permission from the owner.
*   Understand the scope of any authorized test.
*   Be mindful of potential disruption to services.
*   Report vulnerabilities responsibly.

This hands-on part is best learned by doing. Start with DVWA or OWASP Juice Shop, follow online guides, and experiment with the tools mentioned.
