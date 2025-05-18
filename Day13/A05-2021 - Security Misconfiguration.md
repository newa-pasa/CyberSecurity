# A05:2021 - Security Misconfiguration

**What it is:**
Security Misconfiguration refers to flaws resulting from incorrectly configured security controls or the lack of necessary security hardening across any part of the application stack. This includes the operating system, web server, application server, database, framework, custom code, and third-party services.

**Common Types / How it Works:**
*   **Unnecessary Features Enabled:** Default services, pages, accounts, or privileges enabled that are not required for the application's functionality (e.g., sample applications, admin consoles).
*   **Default Credentials:** Using default usernames and passwords for servers, frameworks, or applications (e.g., "admin/admin").
*   **Verbose Error Messages:** Error messages revealing sensitive system information, stack traces, or internal paths that can aid an attacker.
*   **Missing or Improper Security Headers:** Lack of HTTP security headers like Content Security Policy (CSP), X-Frame-Options, HTTP Strict Transport Security (HSTS), X-Content-Type-Options.
*   **Unpatched Systems:** Running outdated software (OS, web server, libraries) with known vulnerabilities.
*   **Directory Listing Enabled:** Web server configured to show the contents of directories if no default page is present.
*   **Cloud Service Misconfigurations:** Improperly configured permissions for cloud storage (e.g., public S3 buckets), overly permissive network access rules for cloud instances.
*   **Outdated Software:** Using software components that are no longer supported or have known vulnerabilities.
*   **Improper File and Directory Permissions:** Overly permissive permissions on sensitive files or directories.
*   **XML Parsers Not Hardened:** Default XML parser configurations might be vulnerable to XXE if not properly secured.

**Potential Impact:**
*   Unauthorized access to systems or data.
*   System compromise.
*   Data leakage.
*   Denial of service.
*   Further attacks on the internal network.

**Basic Prevention:**
*   **Hardening Process:** Establish a repeatable hardening process for all parts of the stack that is fast, easy to deploy, and automated. Maintain different configurations for development, QA, and production environments.
*   **Minimal Platform:** Remove or do not install unused features, components, libraries, and frameworks.
*   **Regular Patch Management:** Keep all software up-to-date, including OS, web/app servers, databases, libraries, and frameworks.
*   **Automated Configuration Verification:** Use automated tools (e.g., configuration management tools, scanners) to verify secure configurations in all environments.
*   **Secure Error Handling:** Configure the application to show generic error messages to users, while logging detailed error information securely for administrators.
*   **Implement Security Headers:** Configure appropriate HTTP security headers.
*   **Secure Cloud Configurations:** Regularly review and audit cloud service configurations using cloud provider tools and third-party solutions.
*   **Disable Directory Listing:** Configure web servers to prevent directory browsing.
*   **Review Default Settings:** Change all default credentials and disable default accounts that are not needed.