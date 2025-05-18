# A09:2021 - Security Logging and Monitoring Failures

**What it is:**
This category covers weaknesses in how an application logs security-relevant events and how those logs are monitored and acted upon. Insufficient logging and monitoring can allow attackers to operate undetected, make forensic analysis difficult, and hinder timely incident response.

**Common Types / How it Works:**
*   **Insufficient Logging:**
    *   Not logging critical security events like logins (successful and failed), access control failures, input validation failures, server-side errors, or high-value transactions.
    *   Logs lacking sufficient detail (e.g., user context, timestamp, source IP) to be useful.
*   **Lack of Monitoring and Alerting:**
    *   Logs are generated but not actively monitored for suspicious activity.
    *   No alerts are configured to notify administrators of potential attacks or critical failures in real-time or near real-time.
*   **Insecure Log Storage:**
    *   Logs stored locally where they can be tampered with or deleted by an attacker who gains system access.
    *   Logs not protected from unauthorized access.
*   **Application Incapable of Detecting Attacks:** The application itself doesn't have mechanisms to detect or escalate alerts for ongoing attacks.
*   **Ineffective Incident Response:** Lack of a documented and practiced incident response plan.
*   **Testing Tools Don't Trigger Alerts:** Penetration tests or DAST scans do not trigger any alerts, indicating monitoring is ineffective.

**Potential Impact:**
*   Delayed detection of breaches, allowing attackers more time to achieve their objectives.
*   Inability to perform effective forensic analysis to understand the scope and cause of an incident.
*   Difficulty in identifying compromised accounts or systems.
*   Increased damage from attacks due to slow response.
*   Non-compliance with regulations that require logging and monitoring.

**Basic Prevention:**
*   **Log Critical Events:**
    *   Ensure all login attempts (successful and failed), access control decisions (especially failures), input validation failures, server-side errors, and high-value transactions are logged with sufficient context (timestamp, source IP, user ID, event details).
    *   Ensure logs are in a common, parsable format.
*   **Centralized and Secure Log Management:**
    *   Send logs to a dedicated, centralized log management system that is secured against tampering and unauthorized access.
    *   Ensure logs have integrity controls.
*   **Effective Monitoring and Alerting:**
    *   Implement real-time or near real-time monitoring of logs for suspicious activities and predefined alert conditions.
    *   Configure alerts to notify appropriate personnel promptly.
*   **Develop an Incident Response Plan:**
    *   Create and regularly test an incident response plan that outlines procedures for handling security incidents.
*   **Protect Log Data:** Ensure log data is encoded correctly to prevent log injection or other attacks against the logging system itself.
*   **Regularly Review Logs and Alerts:** Periodically review logs and alert thresholds to ensure they are effective and to identify trends or anomalies.
*   **Integrate with SIEM:** Use Security Information and Event Management (SIEM) systems to correlate events from various sources and provide a comprehensive view of security posture.