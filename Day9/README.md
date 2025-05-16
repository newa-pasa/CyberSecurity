# Introduction to Ethical Hacking & Pentesting

*   **Core Idea:** Using hacking methodologies and tools for defensive purposes, rather than malicious ones.
*   **Goal:** To identify and fix security vulnerabilities in systems, networks, and applications before malicious attackers can exploit them.
*   **Ethical Hacking:** The broader practice of finding security flaws with permission. It encompasses various security testing activities.
*   **Penetration Testing (Pentesting):** A specific, structured engagement within ethical hacking. It simulates an attack on specific systems or applications to assess their security posture under controlled conditions.
*   **Key Principle:** Always requires explicit, documented permission and operates within a defined scope and rules of engagement.

## What is Ethical Hacking?

*   **Definition:** An authorized practice of attempting to bypass system security mechanisms to identify potential data breaches and threats in a network or system.
*   **Purpose:**
    *   Uncover vulnerabilities from an attacker's perspective.
    *   Implement a secure network/system that prevents security breaches.
    *   Safeguard user data and organizational reputation.
    *   Help organizations understand their security posture and prioritize remediation efforts.
*   **Characteristics:**
    *   **Legal:** Operates with explicit permission from the target organization.
    *   **Scoped:** Testing is confined to predetermined systems, methods, and timeframes.
    *   **Objective:** To improve security, not cause damage or steal information.
    *   **Reported:** Findings (vulnerabilities, risks, recommendations) are documented and delivered to the client.
*   **Also Known As:** White-hat hacking. Contrasts with Black-hat (malicious) and Grey-hat (often without permission, ambiguous intent).

## Penetration Testing Lifecycle

The Penetration Testing Lifecycle provides a structured methodology for conducting security assessments. It ensures a systematic approach, covering all necessary steps from initial planning to final reporting. While specific phases might be named slightly differently or combined depending on the methodology (e.g., PTES, OSSTMM), the core activities remain consistent.

Here are the typical stages:

1.  **Pre-engagement Interactions (Planning & Scoping):**
    *   **Importance:** This is arguably the *most critical* phase, setting the foundation for the entire test.
    *   **Activities:**
        *   Defining clear objectives and goals for the penetration test.
        *   Establishing the **Scope:** What systems, networks, applications, or IP ranges are *in scope* and *out of scope*.
        *   Determining the **Rules of Engagement (RoE):** Defining acceptable testing times, methods, communication protocols, and escalation points.
        *   Handling **Legal Agreements:** Signing contracts, NDAs, and obtaining explicit, written authorization.
        *   Resource allocation and timeline definition.

2.  **Reconnaissance (Information Gathering):**
    *   **Goal:** To gather as much information as possible about the target organization and its systems *before* launching active attacks.
    *   **Types:**
        *   **Passive Reconnaissance:** Gathering information from publicly available sources without direct interaction (e.g., OSINT, `whois`, Google Dorking, Shodan, Maltego). Low risk of detection.
        *   **Active Reconnaissance:** Directly probing the target's systems (e.g., basic network sweeps, port scanning, DNS zone transfers). Higher risk of detection.

3.  **Scanning & Enumeration (Vulnerability Analysis):**
    *   **Goal:** To identify live hosts, open ports, running services, operating systems, and potential vulnerabilities within the scope.
    *   **Activities:**
        *   **Scanning:** Using automated tools for port, network, and vulnerability scanning (e.g., Nmap, Nessus, OpenVAS).
        *   **Enumeration:** Actively querying systems to extract detailed information (e.g., usernames, shares, software versions via tools like enum4linux, SNMPwalk).

4.  **Gaining Access (Exploitation):**
    *   **Goal:** To leverage identified vulnerabilities to breach the target system or application.
    *   **Activities:**
        *   Selecting and executing appropriate exploits (e.g., using Metasploit Framework, SQLMap, Burp Suite).
        *   Bypassing security controls.
        *   Using techniques like password cracking (Hydra, John the Ripper) or social engineering.
    *   **Objective:** Gain a foothold (e.g., command shell, application control).

5.  **Post-Exploitation (Maintaining Access & Analysis):**
    *   **Goal:** Determine the value of the compromised system and potentially gain deeper access.
    *   **Activities:**
        *   **Privilege Escalation:** Gaining higher-level permissions (e.g., using LinPEAS/WinPEAS, Mimikatz).
        *   **Maintaining Access (Persistence):** Installing mechanisms for continued access (e.g., backdoors, services).
        *   **Pivoting:** Using the compromised system to attack other internal systems.
        *   **Internal Reconnaissance:** Mapping the internal network (e.g., using BloodHound).
        *   **Data Exfiltration (Simulated):** Identifying and extracting sensitive data to demonstrate impact.

6.  **Analysis & Reporting:**
    *   **Goal:** Analyze findings, assess business risk, and communicate results clearly to the client.
    *   **Activities:**
        *   Correlating data and prioritizing vulnerabilities (e.g., using CVSS).
        *   Documenting the process, findings (with evidence), and exploitation attempts.
        *   Providing clear, actionable **Remediation Recommendations**.
        *   Creating a comprehensive report (Executive Summary, Technical Details).

7.  **Cleanup (Post-engagement):**
    *   **Goal:** Return client systems to their pre-test state.
    *   **Activities:**
        *   Removing tools, scripts, persistence mechanisms.
        *   Deleting test accounts.
        *   Reverting configuration changes.

---

## Tools Relevant to Penetration Testing Lifecycle Stages

| Stage                       | Relevant Tools (Examples)                                                                 | Notes                                                                 |
| :-------------------------- | :---------------------------------------------------------------------------------------- | :-------------------------------------------------------------------- |
| **Pre-engagement**          | Documentation Tools (Word, Google Docs), Project Management Tools (Jira, Trello)          | Primarily process and documentation-driven.                           |
| **Reconnaissance (Passive)**| Google Search (Dorking), `whois`, `nslookup`/`dig`, Shodan, Maltego, theHarvester, Sublist3r | Gathering public info without direct contact.                         |
| **Reconnaissance (Active)** | Nmap (host discovery `-sn`), `ping`, DNS Zone Transfer tools                              | Initial direct probes.                                                |
| **Scanning & Enumeration**  | Nmap (full scans), Nessus, OpenVAS, Nikto, Dirb/Gobuster, enum4linux, SNMPwalk, WPScan    | Probing for ports, services, vulnerabilities.                         |
| **Gaining Access (Exploitation)** | Metasploit Framework, Burp Suite, SQLMap, Hydra, John the Ripper, SearchSploit, Exploit-DB | Leveraging vulnerabilities for entry.                                 |
| **Post-Exploitation**       | Metasploit (Meterpreter), PowerShell Empire, Cobalt Strike, Mimikatz, BloodHound, PowerSploit, LinPEAS/WinPEAS | Actions after compromise: escalation, persistence, pivoting.          |
| **Analysis & Reporting**     | Word Processors, Spreadsheets, Screenshot Tools, Dradis, Serpico, Scanner Reports         | Documenting findings, risk assessment, recommendations.               |
| **Cleanup**                 | (Manual Removal), Test Scripts (for removal), Metasploit (session cleanup)                | Removing test artifacts.                                              |

**Disclaimer:** This list is not exhaustive. Tool selection depends on scope, target, tester preference, and tool type (commercial/open-source). Many tools span multiple phases.
