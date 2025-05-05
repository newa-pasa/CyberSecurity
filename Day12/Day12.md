# Vulnerability Assessment

*   **Definition:** The systematic process of identifying, quantifying, and prioritizing (or ranking) the vulnerabilities in a system, network, or application.
*   **Goal:** To provide the organization with the necessary knowledge and risk background to understand the threats to its environment and react appropriately. It's a key part of a comprehensive risk management program.
*   **Process Overview:**
    1.  **Planning & Scoping:** Define the assets to be assessed, the methods to be used, and the objectives of the assessment.
    2.  **Information Gathering & Scanning:** Use various tools and techniques (like port scanners, vulnerability scanners) to identify open ports, running services, system information, and potential vulnerabilities.
    3.  **Vulnerability Analysis:** Analyze the scan results, eliminate false positives, and correlate findings to understand the specific weaknesses.
    4.  **Reporting:** Document the findings, including identified vulnerabilities, their severity, potential impact, and recommended remediation steps.
    5.  **Remediation & Rescan:** Apply fixes or mitigations and then rescan to verify that the vulnerabilities have been addressed.

## Common Vulnerabilities & Exploits (CVE, CVSS)

### Common Vulnerabilities and Exposures (CVE)
*   **What it is:** A dictionary or list of publicly disclosed cybersecurity vulnerabilities and exposures. Maintained by the MITRE Corporation with funding from the US Division of Homeland Security (DHS).
*   **Purpose:** To provide a standardized identifier (CVE ID) for a specific, unique vulnerability. This allows security professionals, vendors, and researchers to refer to the same issue consistently across different tools, databases, and reports.
*   **Format:** `CVE-YYYY-NNNNN`
    *   `CVE`: Prefix indicating it's a CVE identifier.
    *   `YYYY`: Year the vulnerability was reported or published.
    *   `NNNNN`: Sequence number (can be 4 or more digits).
*   **Example:** `CVE-2017-0144` refers to the EternalBlue vulnerability in Microsoft's SMB protocol.
*   **Key Point:** CVE *identifies* the vulnerability; it doesn't rate its severity. That's where CVSS comes in.

### Common Vulnerability Scoring System (CVSS)
*   **What it is:** An open industry standard for assessing the severity of computer system security vulnerabilities. It provides a numerical score (0-10) reflecting severity, along with a qualitative representation (Low, Medium, High, Critical). Maintained by FIRST.Org, Inc. (Forum of Incident Response and Security Teams).
*   **Purpose:** To provide a standardized, objective way to communicate the characteristics and severity of vulnerabilities, helping organizations prioritize remediation efforts.
*   **Versions:** CVSS v2, CVSS v3.0, CVSS v3.1 (most current). v3.x provides more granularity and better reflects modern threats compared to v2.
*   **Metric Groups (CVSS v3.x):**
    *   **Base Score:** Represents the intrinsic qualities of a vulnerability that are constant over time and user environments.
        *   *Exploitability Metrics:* Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI).
        *   *Impact Metrics:* Confidentiality (C), Integrity (I), Availability (A).
        *   *Scope (S):* Whether a vulnerability in one component impacts resources beyond its security scope.
    *   **Temporal Score:** Reflects characteristics that change over time, such as the availability of exploit code or patches. (Exploit Code Maturity, Remediation Level, Report Confidence). Often adjusts the Base Score downwards if mitigations are available.
    *   **Environmental Score:** Represents characteristics relevant to a specific user's environment. Allows organizations to customize the score based on mitigating controls they have in place or the importance of the affected asset. (Modified Base Metrics, Confidentiality/Integrity/Availability Requirements).
*   **Severity Ratings (CVSS v3.x):**
    *   0.0: None
    *   0.1 - 3.9: Low
    *   4.0 - 6.9: Medium
    *   7.0 - 8.9: High
    *   9.0 - 10.0: Critical
*   **Usage:** CVE IDs are often accompanied by a CVSS score in vulnerability databases and scanner reports.

## Hands-on: Using Nessus for vulnerability scanning

*   **What it is:** Nessus is one of the most widely used vulnerability scanners. Developed by Tenable, it scans systems, networks, and applications for known vulnerabilities, misconfigurations, and missing patches.
*   **Versions:**
    *   **Nessus Essentials (formerly Home):** Free version, limited to scanning 16 IP addresses. Good for learning and small home networks.
    *   **Nessus Professional:** Paid version, unlimited IPs, includes compliance checks, content audits, live results, and can be used for commercial purposes. The standard for consultants and enterprise teams.
    *   **Tenable.io / Tenable.sc (formerly SecurityCenter):** Enterprise platforms that use Nessus scanners but add centralized management, reporting, broader asset coverage (web apps, cloud), and risk prioritization features.
*   **Basic Scan Process (Nessus Professional/Essentials):**
    1.  **Installation & Setup:** Download and install Nessus on a supported OS (Windows, macOS, Linux). Activate using a license key (Professional) or register for Essentials. Access the web interface (usually `https://localhost:8834`).
    2.  **Create a New Scan:** Click "New Scan". Nessus offers various pre-built scan templates (e.g., Basic Network Scan, Advanced Scan, Web Application Tests, Credentialed Patch Audit, Malware Scan).
    3.  **Configure Scan Settings:**
        *   **General:** Give the scan a name and description. Specify the target IP addresses, ranges (CIDR notation), or hostnames.
        *   **Discovery:** Configure host discovery methods (ARP, ICMP, TCP, UDP pings) and port scanning options (range, common ports, all ports).
        *   **Assessment:** Choose the type of vulnerability checks to perform (e.g., Windows, Linux, Web Servers, Databases).
        *   **Report:** Configure report details.
        *   **Advanced:** Fine-tune performance (e.g., max simultaneous checks/hosts) and other advanced settings.
        *   **(Optional but Recommended) Credentials:** Provide credentials (e.g., SSH for Linux/Mac, SMB/WMI for Windows) for the target systems. *Credentialed scans* (authenticated scans) are far more accurate as Nessus can log in and check patch levels, detailed configurations, and software versions directly, finding vulnerabilities missed by unauthenticated scans.
    4.  **Launch the Scan:** Save the configuration and launch the scan. Duration depends on the number of targets, scan intensity, and network latency.
    5.  **Analyze Results:** Once complete, click on the scan report.
        *   View vulnerabilities grouped by severity (Critical, High, Medium, Low, Info).
        *   Click on a specific vulnerability to see details: Description, Synopsis, Solution (remediation steps), CVE ID, CVSS score, affected hosts, port/service, plugin output (evidence).
        *   Filter and sort results.
        *   Export the report (e.g., PDF, HTML, CSV) for documentation and sharing.
*   **Key Considerations:**
    *   **Scope:** Always ensure you have explicit permission to scan the target systems.
    *   **Scan Type:** Choose the appropriate scan template and configure credentials for best results.
    *   **False Positives/Negatives:** No scanner is perfect. Results should be validated. False positives (scanner reports a vulnerability that doesn't exist) and false negatives (scanner misses a real vulnerability) can occur.
    *   **Performance Impact:** Intensive scans can consume network bandwidth and target system resources. Schedule scans during off-peak hours if necessary.




### Projects to practice 

There are several other excellent intentionally vulnerable web applications similar to OWASP Juice Shop and Damn Vulnerable Web Application (DVWA) that you can use for learning and practicing web security. Here are some popular ones, often recommended as alternatives or complements:

**OWASP Projects:**

* **OWASP WebGoat:** Another flagship project by OWASP, WebGoat is a deliberately insecure Java-based web application. It focuses on teaching web application security vulnerabilities with interactive lessons where you exploit real flaws. It covers a wide range of OWASP Top Ten vulnerabilities and more.
* **OWASP Mutillidae II:** A free, open-source, deliberately vulnerable web application created and maintained by OWASP. It's designed as a target for web security training and covers a vast array of vulnerabilities, with different security levels and hints to guide users.
* **OWASP Zed Attack Proxy (ZAP):** While primarily a penetration testing tool, ZAP includes deliberately vulnerable applications as part of its training and demonstration features.

**Other Popular Vulnerable Web Applications:**

* **bWAPP (Buggy Web Application):** A free and open-source PHP web application containing over 100 web vulnerabilities. It's designed to be comprehensive and covers all risks from the OWASP Top 10 project. It's relatively easy to set up and use.
* **XVWA (Xtreme Vulnerable Web Application):** A badly coded PHP/MySQL web application designed to help security enthusiasts learn about application security. It covers various common web vulnerabilities.
* **Web Security Dojo (WSD):** A virtual machine that comes pre-loaded with various security tools and vulnerable web applications, including WebGoat and Hacme Casino. It provides a ready-to-go environment for learning.
* **Badstore:** A deliberately vulnerable PHP e-commerce application with a wide range of security flaws, including SQL injection, XSS, and more. It's often used for practicing various attack techniques.
* **Google Gruyere:** A "cheesy" web application intentionally designed to be full of security vulnerabilities. It's a good option for beginners to learn how to find and exploit common flaws.
* **Hackazon:** A modern, vulnerable web application inspired by real-world e-commerce platforms. It aims to provide a more realistic and challenging environment for penetration testing practice.
* **Security Shepherd:** A web and mobile application security training platform with challenges covering various vulnerability categories. It also includes aspects of mobile app penetration testing.
* **Altoro Mutual:** A vulnerable online banking web application often used for demonstrations and training related to web security testing.
* **Bricks:** A deliberately vulnerable web application built with Python and Flask, designed for learning web security concepts.
* **BodgeIt Store:** A simple, intentionally vulnerable web application written in Java, suitable for beginners to learn about common web vulnerabilities.
* **Damn Vulnerable Node Application (DVNA):** Similar to DVWA but built with Node.js. It's a good option for practicing vulnerabilities specific to Node.js applications.

**Online Platforms with Vulnerable Labs:**

While not applications you host directly, platforms like **TryHackMe** and **Hack The Box** often have dedicated vulnerable web application labs that you can access through their platform. These provide a more guided learning experience in some cases.

**Choosing the Right Application:**

The best application for you will depend on your learning goals and technical background.

* **Beginners:** DVWA, bWAPP, and Gruyere are often recommended as good starting points due to their ease of setup and clear vulnerabilities.
* **Java Focus:** WebGoat is excellent for practicing Java-based web application vulnerabilities.
* **Comprehensive Coverage:** Mutillidae II and bWAPP offer a wide range of vulnerabilities to explore.
* **Modern Applications:** OWASP Juice Shop and Hackazon provide more modern and realistic scenarios.

Many of these applications can be run using Docker, which simplifies the setup process by handling dependencies. You can search for Docker images of these applications on Docker Hub. You can also often find pre-built virtual machine images (OVA files) for VirtualBox or VMware.

Remember to always run these vulnerable applications in a safe and isolated environment, such as a virtual machine, to avoid any unintended security risks to your main system. Happy hacking (ethically)!