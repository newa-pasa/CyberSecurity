# A07:2021 - Identification and Authentication Failures

**(Previously "Broken Authentication")**

**What it is:**
This category covers vulnerabilities related to how an application confirms user identity (identification), verifies that identity (authentication), and manages user sessions. Failures can allow attackers to compromise legitimate user accounts, passwords, or session tokens, or to exploit other implementation flaws to assume other users' identities.

**Common Types / How it Works:**
*   **Permitting Brute-Force Attacks:**
    *   Allowing automated credential stuffing (using lists of breached credentials).
    *   Allowing password spraying (trying common passwords against many usernames).
    *   Not implementing account lockout or rate limiting on login attempts.
*   **Weak or Ineffective Credential Recovery:** Password reset or "forgot password" processes that are easily subverted (e.g., predictable reset tokens, knowledge-based answers that are easy to guess).
*   **Weak Passwords:**
    *   Allowing users to set weak, common, or easily guessable passwords.
    *   Not enforcing strong password policies.
    *   Using default credentials.
*   **Session Management Flaws:**
    *   Exposing Session IDs in URLs (can be logged by browsers, proxies, or referer headers).
    *   Session tokens not having sufficient randomness or entropy, making them guessable.
    *   Sessions not being properly invalidated on logout, idle timeout, or absolute timeout.
    *   Session fixation: Attacker tricks a user into using a session ID known to the attacker.
*   **Missing or Weak Multi-Factor Authentication (MFA):** Not implementing MFA, or implementing it in a way that can be bypassed.
*   **Insecure Password Storage:** Storing passwords in plain text, or using weak, non-salted, or easily reversible hashing algorithms.
*   **Username Enumeration:** Allowing an attacker to determine valid usernames based on different responses from login or password reset pages.

**Potential Impact:**
*   Unauthorized access to user accounts.
*   Identity theft.
*   Privilege escalation if an administrative account is compromised.
*   Data breaches.

**Basic Prevention:**
*   **Implement Multi-Factor Authentication (MFA):** Enforce MFA for all users, especially for sensitive accounts.
*   **Strong Password Policies:** Enforce strong password complexity, length, and rotation policies (aligned with NIST 800-63B or similar guidelines). Implement checks against common/breached passwords.
*   **Secure Credential Storage:** Store passwords using strong, adaptive, and salted hashing functions (e.g., Argon2, scrypt, bcrypt).
*   **Protect Against Automated Attacks:**
    *   Implement account lockout or progressive delays after a certain number of failed login attempts.
    *   Use CAPTCHAs or similar mechanisms to deter bots.
    *   Monitor for credential stuffing and password spraying attacks.
*   **Secure Session Management:**
    *   Generate strong, random session IDs on the server-side.
    *   Do not expose session IDs in URLs; transmit them in secure cookies (HttpOnly, Secure flags).
    *   Properly invalidate sessions on logout, idle timeout, and absolute timeout. Regenerate session IDs after login.
*   **Secure Credential Recovery:** Implement secure password reset mechanisms (e.g., time-limited, single-use tokens sent via a secure out-of-band channel).
*   **Avoid Username Enumeration:** Ensure login and password reset pages give generic responses for invalid usernames or passwords.
*   **Do Not Ship with Default Credentials:** Change all default credentials before deployment.