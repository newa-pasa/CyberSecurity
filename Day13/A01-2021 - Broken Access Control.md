# A01:2021 - Broken Access Control

**What it is:**
Broken Access Control encompasses vulnerabilities where restrictions on what authenticated users are allowed to do are not properly enforced. This means users can gain access to unauthorized functionality or data, such as accessing other users' accounts, viewing sensitive files, or modifying other users' data.

**Common Types / How it Works:**
*   **Bypassing Access Control Checks:** Attackers modify parameters in the URL, change the HTTP method (e.g., from GET to POST), or manipulate API requests to access functions they shouldn't.
*   **Privilege Escalation:**
    *   **Vertical Privilege Escalation:** A user gains access to functionality reserved for users with higher privileges (e.g., a regular user accessing admin functions).
    *   **Horizontal Privilege Escalation:** A user gains access to resources belonging to another user with similar privileges (e.g., viewing another user's profile or orders).
*   **Insecure Direct Object References (IDOR):** An application uses user-supplied input to access objects directly. Attackers can manipulate these references (e.g., changing `?invoice_id=101` to `?invoice_id=102`) to access unauthorized data.
*   **Missing Function-Level Access Control:** Specific functions or API endpoints might lack checks to verify if the requesting user is authorized to perform the action, even if they are authenticated.
*   **CORS Misconfiguration:** Overly permissive Cross-Origin Resource Sharing (CORS) policies can allow unauthorized websites to make requests to the application on behalf of a user, potentially leading to data exfiltration or unauthorized actions.
*   **Forcing Browsing:** Accessing locations that are not meant to be publicly accessible by guessing URLs for restricted areas or resources.

**Potential Impact:**
*   Unauthorized viewing, modification, or deletion of data.
*   Performing actions on behalf of other users.
*   Gaining administrative access to the application.
*   Exposure of sensitive information.

**Basic Prevention:**
*   **Deny by Default:** Access control should be implemented with a "deny by default" principle, only granting access explicitly.
*   **Centralized Access Control Mechanisms:** Implement access control checks in a central, reusable component or library.
*   **Enforce Record Ownership:** Ensure users can only access records they own or are explicitly authorized to access.
*   **Model Access Controls to Business Rules:** Access controls should reflect the actual business rules and user roles.
*   **Disable Web Server Directory Listing:** Prevent users from browsing directory contents.
*   **Log Access Control Failures:** Log all access control failures and generate alerts for repeated or suspicious attempts.
*   **Rate Limit API and Controller Access:** To slow down automated attempts to find access control flaws.
*   **Verify Access at Each Tier:** Access control decisions should be enforced on the trusted server-side.