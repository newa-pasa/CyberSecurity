# Cybersecurity Laws & Ethics

## Cybersecurity regulations (GDPR, ISO 27001, PCI-DSS, IT Act 2000)

### General Data Protection Regulation (GDPR)
*   **What it is:** A comprehensive data protection law enacted by the European Union (EU) in 2018. It aims to give individuals control over their personal data and simplify the regulatory environment for international business by unifying regulation within the EU.
*   **Scope:** Applies to any organization, regardless of location, that processes the personal data of individuals residing in the EU or European Economic Area (EEA).
*   **Key Principles/Requirements:**
    *   **Lawfulness, Fairness, and Transparency:** Processing must be lawful, fair, and transparent to the data subject.
    *   **Purpose Limitation:** Data collected for specified, explicit, and legitimate purposes should not be further processed in a manner incompatible with those purposes.
    *   **Data Minimization:** Data collected should be adequate, relevant, and limited to what is necessary for the intended purpose.
    *   **Accuracy:** Personal data should be accurate and kept up to date.
    *   **Storage Limitation:** Data should be kept in a form that permits identification of data subjects for no longer than necessary.
    *   **Integrity and Confidentiality:** Data must be processed securely, protecting against unauthorized or unlawful processing, accidental loss, destruction, or damage.
    *   **Accountability:** The data controller is responsible for demonstrating compliance with these principles.
*   **Individual Rights:** Includes the right to access, rectify, erase ("right to be forgotten"), restrict processing, data portability, and object to processing.
*   **Non-compliance:** Can result in significant fines (up to €20 million or 4% of global annual turnover, whichever is higher).

### ISO 27001
*   **What it is:** An international standard for establishing, implementing, maintaining, and continually improving an Information Security Management System (ISMS). It provides a systematic approach to managing sensitive company information.
*   **Scope:** Applicable to organizations of any size or industry. Certification is optional but demonstrates a commitment to information security best practices.
*   **Key Components:**
    *   **Risk Assessment:** Identifying threats, vulnerabilities, and potential impacts on information assets.
    *   **Security Controls:** Implementing controls (technical, physical, administrative) based on risk assessment. Annex A provides a list of common controls.
    *   **Management Commitment:** Requires top management involvement and support.
    *   **Documentation:** Maintaining policies, procedures, and records related to the ISMS.
    *   **Internal Audits:** Regularly reviewing the effectiveness of the ISMS.
    *   **Continuous Improvement:** Regularly updating the ISMS based on audits, reviews, and changing threats.
*   **Benefits:** Enhanced information security posture, increased customer trust, compliance with legal/regulatory requirements, improved risk management.

### Payment Card Industry Data Security Standard (PCI-DSS)
*   **What it is:** A set of security standards designed to ensure that all companies that accept, process, store, or transmit credit card information maintain a secure environment. It was created by major payment card brands (Visa, MasterCard, American Express, Discover, JCB).
*   **Scope:** Applies to any organization that handles cardholder data, regardless of size or transaction volume.
*   **Key Requirements (12 Core Requirements):**
    1.  Install and maintain a firewall configuration to protect cardholder data.
    2.  Do not use vendor-supplied defaults for system passwords and other security parameters.
    3.  Protect stored cardholder data (e.g., through encryption, masking).
    4.  Encrypt transmission of cardholder data across open, public networks.
    5.  Protect all systems against malware and regularly update anti-virus software.
    6.  Develop and maintain secure systems and applications.
    7.  Restrict access to cardholder data by business need-to-know.
    8.  Identify and authenticate access to system components.
    9.  Restrict physical access to cardholder data.
    10. Track and monitor all access to network resources and cardholder data.
    11. Regularly test security systems and processes (e.g., vulnerability scanning, penetration testing).
    12. Maintain a policy that addresses information security for all personnel.
*   **Non-compliance:** Can lead to fines, increased transaction fees, loss of ability to process card payments, and reputational damage.

### Information Technology Act, 2000 (IT Act 2000 - India)
*   **What it is:** The primary law in India dealing with cybercrime and electronic commerce. It provides legal recognition for electronic transactions and aims to prevent computer misuse. Amended significantly by the IT Amendment Act, 2008.
*   **Scope:** Applies to offenses or contraventions committed within and outside India if the computer, computer system, or network involved is located in India.
*   **Key Provisions:**
    *   **Legal Recognition:** Grants legal status to electronic documents and digital signatures.
    *   **Cybercrimes:** Defines and prescribes punishments for various cybercrimes like hacking (Section 66), identity theft (Section 66C), cheating by personation (Section 66D), violation of privacy (Section 66E), cyber terrorism (Section 66F), publishing obscene information (Section 67), child pornography (Section 67B), etc.
    *   **Data Protection (Section 43A):** Requires bodies corporate handling sensitive personal data to implement reasonable security practices. Failure resulting in wrongful loss or gain leads to liability to pay damages.
    *   **Intermediary Liability (Section 79):** Provides safe harbor provisions for intermediaries (like ISPs, social media platforms) under certain conditions, but they must exercise due diligence.
    *   **Adjudicating Officers & Cyber Appellate Tribunal:** Establishes mechanisms for resolving disputes and hearing appeals.
*   **Relevance:** Crucial for understanding legal liabilities and protections related to digital activities and data handling within India.

## Ethical hacking guidelines & responsible disclosure

### Ethical Hacking Guidelines
*   **Definition:** Ethical hacking (or penetration testing) involves legally attempting to break into computer systems and networks to test an organization's defenses and identify vulnerabilities before malicious actors do.
*   **Core Principles:**
    *   **Legality & Permission:** Obtain explicit, written permission from the asset owner before conducting any testing. Define the scope clearly.
    *   **Scope:** Strictly adhere to the agreed-upon scope of the assessment. Do not test systems or data outside the defined boundaries.
    *   **Do No Harm:** Conduct tests in a way that minimizes disruption to business operations and avoids damaging systems or data.
    *   **Confidentiality:** Respect the privacy and confidentiality of any data accessed during the assessment. Report findings only to the authorized personnel.
    *   **Report Vulnerabilities:** Document all findings thoroughly, including identified vulnerabilities, potential impact, and recommended remediation steps.

### Responsible Disclosure
*   **Definition:** A process where security researchers (or ethical hackers) find vulnerabilities in software, systems, or websites and report them privately to the vendor or organization responsible, allowing them time to fix the issue before disclosing it publicly.
*   **Process:**
    1.  **Discovery:** Identify a potential security vulnerability.
    2.  **Private Reporting:** Contact the vendor/organization through designated security channels (e.g., security@ email, bug bounty platform). Provide detailed technical information about the vulnerability.
    3.  **Vendor Acknowledgment & Remediation:** The vendor acknowledges the report, investigates, develops a patch, and deploys it. This phase often involves communication between the researcher and vendor. A reasonable timeframe is usually agreed upon (e.g., 90 days).
    4.  **Public Disclosure:** Once the vulnerability is fixed, or after the agreed timeframe has passed (even if unfixed, in some models), the researcher and/or vendor may publicly disclose details about the vulnerability. This informs the wider community and encourages users to patch.
*   **Importance:** Balances the need to fix vulnerabilities quickly (protecting users) with the public's right to know about risks. It encourages collaboration between researchers and organizations, fostering a more secure ecosystem compared to full public disclosure without prior warning or non-disclosure (keeping users vulnerable).


## Referances 
- https://worldpopulationreview.com/country-rankings/gdpr-countries
- https://www.unifocus.com/security-and-compliance
- https://legaltechnology.com/2021/04/28/is-it-legal-to-track-employees-with-vehicle-gps-tracking/
- https://www.horus-security.co.uk/news/
- https://securitybriefing.net/tech/regulatory-and-standard-compliance/
- https://www.lightspeedhq.co.uk/blog/pci-compliance/
- https://www.security.org/resources/consumer-data-security/
- https://www.tripwire.com/state-of-security/pci-dss-4-0-iso-27001-dynamic-duo
- https://stripe.com/guides/pci-compliance
- https://www.michalsons.com/blog/pci-dss-compliance/46