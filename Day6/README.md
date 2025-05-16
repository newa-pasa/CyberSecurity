# Cyber Threats & Social Engineering

## Phishing and Related Social Engineering Attacks

Social engineering is the art of manipulating people into performing actions or divulging confidential information. Phishing and its variants are common forms of social engineering attacks focused on obtaining sensitive data like credentials, credit card numbers, or personal information.

### 1. Phishing

*   **Definition:** A broad attack where attackers send deceptive emails, messages, or create fake websites impersonating legitimate organizations (banks, social media, online retailers, etc.) to trick a large number of recipients into revealing sensitive information.
*   **Mechanism:** Typically involves casting a wide net with generic messages. These messages often create a sense of urgency, fear, or curiosity.
    *   *Example Lures:* "Your account has been compromised, click here to verify," "You have an unpaid invoice," "Click here to claim your prize," "Verify your login details."
*   **Goal:** Harvest credentials, install malware via malicious links or attachments, or trick users into making fraudulent payments.
*   **Indicators:** Generic greetings ("Dear Customer"), poor grammar/spelling, urgent calls to action, requests for sensitive information, mismatched URLs (hover over links!), unexpected attachments, sender email address doesn't match the legitimate domain.

### 2. Spear Phishing

*   **Definition:** A highly targeted form of phishing directed at specific individuals, organizations, or groups.
*   **Mechanism:** Attackers research their targets (using LinkedIn, company websites, social media) to craft personalized and highly convincing messages. The email might appear to come from a known colleague, manager, vendor, or trusted entity.
    *   *Example Lures:* An email seemingly from HR about a policy update with a malicious attachment, a message appearing to be from the CEO requesting an urgent wire transfer (CEO Fraud/Business Email Compromise - BEC), a fake login page for a company-specific portal.
*   **Goal:** Same as phishing, but often more specific, like gaining access to a particular corporate network, stealing specific intellectual property, or initiating larger financial fraud.
*   **Indicators:** Highly personalized content, references specific projects or colleagues, may have better grammar/spelling than generic phishing, sender address might be subtly spoofed (e.g., `ceo@company-corp.com` instead of `ceo@company.com`). The targeted nature makes them harder to detect.

### 3. Smishing (SMS Phishing)

*   **Definition:** Phishing conducted via SMS (text messages).
*   **Mechanism:** Uses text messages to lure victims. Often leverages urgency and the inherent trust people place in SMS notifications.
    *   *Example Lures:* Fake delivery notifications ("Your package has a problem, click here: [malicious link]"), bank alerts ("Suspicious activity detected on your account: [malicious link]"), fake prize winnings, urgent requests seemingly from contacts.
*   **Goal:** Trick users into clicking malicious links (leading to fake login pages or malware), calling premium-rate numbers, or revealing personal information.
*   **Indicators:** Unsolicited messages, urgent requests, links using URL shorteners, requests for personal data via text.

### 4. Vishing (Voice Phishing)

*   **Definition:** Phishing conducted over voice calls (telephone).
*   **Mechanism:** Attackers call victims impersonating legitimate entities (banks, tech support, government agencies like the IRS or police, utility companies). They use social engineering techniques like authority, intimidation, or helpfulness to manipulate victims.
    *   *Example Lures:* Fake tech support calls claiming your computer is infected (asking for remote access or payment), impersonating bank fraud departments asking to "verify" account details or card numbers, threats of arrest if a fake fine isn't paid immediately.
*   **Goal:** Extract sensitive information (passwords, credit card numbers, Social Security numbers), gain remote access to computers, or coerce victims into sending money.
*   **Indicators:** Unsolicited calls demanding immediate action or payment, requests for sensitive information over the phone, threats, caller ID spoofing (number may look legitimate), offers that sound too good to be true.

### Tools Used in Phishing Attacks (Attacker Perspective)

*   **Email Spoofing Tools:** Software or services to make emails appear as if they originate from a legitimate sender.
*   **Phishing Frameworks:**
    *   **Gophish:** Open-source phishing framework for setting up and launching phishing campaigns, tracking results.
    *   **Social-Engineer Toolkit (SET):** (Often included in Kali Linux) A Python-driven tool aimed at penetration testing around social-engineering. Can create fake login pages, malicious payloads, etc.
*   **Website Cloning Tools:** Tools like HTTrack can be used to quickly clone legitimate websites (like login pages) for use in phishing campaigns.
*   **Bulk Email/SMS Services:** Used to send out large volumes of phishing messages.
*   **URL Shorteners:** Used to obfuscate malicious links.

### Mitigation and Defense

*   **User Awareness Training:** Crucial first line of defense. Train users to recognize phishing indicators.
*   **Verify Requests:** Always verify urgent or unusual requests (especially financial ones) through a separate, trusted communication channel (e.g., call the person directly using a known number, not one from the email).
*   **Scrutinize Links and Senders:** Hover over links to see the actual URL. Check sender email addresses carefully for subtle differences.
*   **Use Strong, Unique Passwords & MFA:** Limits the damage if credentials are stolen.
*   **Technical Controls:** Implement email filtering (spam, anti-phishing), DMARC/SPF/DKIM email authentication, URL filtering/scanning, endpoint security solutions.
*   **Never Provide Sensitive Info:** Legitimate organizations rarely ask for passwords, full credit card numbers, or SSNs via email, SMS, or unsolicited calls.
*   **Report Suspicious Messages:** Report phishing attempts to your IT/security department or email provider.

---

## Password Attacks & Brute Force Attacks

Password attacks aim to gain unauthorized access to accounts, systems, or data by guessing, cracking, or bypassing password authentication mechanisms.

### 1. Brute Force Attack

*   **Definition:** Systematically trying every possible combination of characters (letters, numbers, symbols) until the correct password is found.
*   **Mechanism:** Automated tools cycle through combinations. The effectiveness depends heavily on password length and complexity, and the computational power available.
    *   *Simple Example:* Trying `a`, `b`, `c`...`aa`, `ab`, `ac`...`1`, `2`, `3`...`a1`, `a2`...
*   **Tools:**
    *   **Hashcat:** A very fast, versatile password recovery tool that supports hundreds of hash types and multiple attack modes, including brute force. Can leverage GPUs for massive speed increases.
        *   *Example (Brute force MD5 hash for 4 digits):*
            ```bash
            # -a 3 specifies brute-force mode
            # -m 0 specifies MD5 hash type
            # ?d represents the digit character set [0-9]
            # ?d?d?d?d means try all combinations of 4 digits
            hashcat -a 3 -m 0 e48e13207341b6bffb7fb1622282247b ?d?d?d?d

            # To show cracked passwords from the potfile later:
            hashcat -a 3 -m 0 e48e13207341b6bffb7fb1622282247b --show
            ```
    *   **John the Ripper (John):** Another popular password cracker, good at auto-detecting hash types. Also supports brute force ("incremental" mode).
    *   **Hydra:** A popular *online* brute-forcing tool for network services (SSH, FTP, Telnet, HTTP login forms, etc.).
        *   *Example (Try password list against SSH admin user):*
            ```bash
            hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.101
            ```
*   **Pros/Cons:** Guaranteed to find the password *eventually* if it's within the tested keyspace, but extremely slow for long, complex passwords.

### 2. Dictionary Attack

*   **Definition:** Trying passwords from a predefined list (a "dictionary") of common words, phrases, previously breached passwords, or relevant terms.
*   **Mechanism:** Uses wordlists instead of trying all combinations. Often combined with rules to mutate words (e.g., `password` -> `Password`, `p@ssword`, `password123`). Much faster than brute force if the password is common or simple.
*   **Tools:**
    *   **John the Ripper:** Excels at dictionary attacks, especially with its rule engine.
        *   *Example (Dictionary attack on MD5 hash using rockyou.txt):*
            ```bash
            # --format=raw-md5 specifies the hash type
            # test.txt contains the hash(es) to crack
            # --wordlist specifies the dictionary file
            john --format=raw-md5 test.txt --wordlist=/usr/share/wordlists/rockyou.txt
            ```
    *   **Hashcat:** Also supports dictionary attacks (`-a 0`). Can be combined with rules (`-r`).
        *   *Example (Dictionary attack):*
            ```bash
            hashcat -a 0 -m 0 hashfile.txt /usr/share/wordlists/rockyou.txt
            ```
    *   **Hydra:** Can use dictionary files (`-P`) for online attacks.
*   **Wordlists:** Common lists include `rockyou.txt`, `cain.txt`, SecLists, etc. Custom lists can be generated based on target information (company name, usernames, hobbies).

### 3. Credential Stuffing

*   **Definition:** Using lists of usernames and passwords stolen from data breaches on one service to attempt logins on other unrelated services.
*   **Mechanism:** Relies on the common user behavior of reusing passwords across multiple sites. Automated tools try known username/password pairs against target login portals.
*   **Tools:** Custom scripts, Sentry MBA (older, often used by attackers), OpenBullet, Burp Suite Intruder, Hydra.

### 4. Password Spraying

*   **Definition:** Trying a small number of common passwords (e.g., `Password123`, `Spring2024`, `CompanyName1`) against a large number of different user accounts.
*   **Mechanism:** Aims to find accounts using weak, common passwords while avoiding account lockouts that might occur from many failed attempts on a single account. Often targets corporate login portals (like OWA, M365, VPNs).
*   **Tools:** Custom scripts, Metasploit modules, `Kerbrute`, `CredMaster`.

### 5. Other Password Attack Vectors

*   **Keylogging:** Malware records keystrokes to capture passwords as they are typed.
*   **Phishing:** Tricking users into entering their credentials on fake login pages.
*   **Rainbow Table Attacks:** Using precomputed tables of hashes to quickly find password matches (less effective against properly salted hashes).
*   **Pass-the-Hash (PtH):** (Windows environments) Using stolen password hashes directly to authenticate without needing the plaintext password. Tools like Mimikatz are used to extract hashes from memory.

### Hash Identification Tools

Before cracking, you need to know the hash type.
*   **Hash Identifier:** A Python script often included in security distros.
    *   *Example:* `hash-identifier cc03e747a6afbbcbf8be7668acfebee5`
*   **HashID:** Another tool for identifying hash types.
*   **haiti:** (Mentioned in `notes.md`) Yet another hash identification tool.
    *   *Example:* `haiti cc03e747a6afbbcbf8be7668acfebee5`
*   Online Hash Analyzers: Websites that attempt to identify hash types.

### Mitigation and Defense

*   **Enforce Strong Password Policies:** Require minimum length, complexity (mix of upper/lower case, numbers, symbols), and disallow common passwords or dictionary words.
*   **Multi-Factor Authentication (MFA):** The single most effective defense against credential theft and reuse.
*   **Account Lockout Policies:** Lock accounts after a certain number of failed login attempts (balance security with usability to avoid DoS).
*   **Rate Limiting:** Limit the number of login attempts allowed from a single IP address in a given time period.
*   **Password Hashing:** Use strong, slow hashing algorithms with unique salts for each password (e.g., bcrypt, Argon2, scrypt). Avoid outdated algorithms like MD5 or SHA1 for password storage.
*   **Password Managers:** Encourage users to use password managers to generate and store strong, unique passwords for each service.
*   **Monitor Logs:** Monitor for large numbers of failed login attempts, logins from unusual locations, or signs of password spraying/credential stuffing.
*   **Breached Password Detection:** Check user passwords against known data breach lists.
*   **User Education:** Train users on creating strong passwords and recognizing phishing attacks.

---
**Disclaimer:** The tools and techniques described should only be used ethically and legally, for authorized security testing or educational purposes. Unauthorized attempts to access accounts or systems are illegal.
