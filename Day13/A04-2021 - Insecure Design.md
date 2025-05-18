# A04:2021 - Insecure Design

**What it is:**
Insecure Design is a broad category representing weaknesses introduced due to missing or ineffective security controls and considerations during the design and architecture phase of software development. It's about flaws in "how" security is implemented, or the lack thereof, rather than specific implementation bugs.

**Common Types / How it Works (Examples of Design Flaws):**
*   **Lack of Business Risk Profiling:** Not considering the potential business impact of security flaws when designing features.
*   **Insecure Design Patterns:** Using or implementing design patterns that inherently have security weaknesses without proper mitigations.
*   **Missing or Ineffective Threat Modeling:** Failing to identify potential threats and design appropriate countermeasures for critical application flows (e.g., authentication, payment processing, access control).
*   **Not Designing for Secure Defaults:** Systems are not secure "out of the box" and require manual hardening.
*   **Flawed Business Logic:** Design flaws in the application's logic that can be exploited (e.g., an e-commerce site allowing negative quantities in a shopping cart leading to fraudulent refunds, race conditions in financial transactions).
*   **Exposing Excessive Functionality:** Internal system details or functionality exposed to users without adequate protection.
*   **Unsafe Resource Management:** Design that allows for resource exhaustion (e.g., unlimited file uploads, unbounded query results).
*   **Trusting Client-Side Controls:** Relying on client-side validation or controls for security, which can be easily bypassed.

**Potential Impact:**
*   Can lead to any of the other OWASP Top 10 vulnerabilities.
*   Financial loss due to exploitation of business logic flaws.
*   Data breaches.
*   System compromise.
*   Denial of service.

**Basic Prevention:**
*   **Establish a Secure Development Lifecycle (SDL):** Integrate security activities throughout all phases of development, from requirements gathering to deployment and maintenance.
*   **Conduct Threat Modeling:** Regularly perform threat modeling for critical components and functionalities to identify potential threats and design mitigations.
*   **Use Secure Design Patterns and Principles:** Adopt well-established secure design patterns and principles like "defense in depth," "fail securely," and "least privilege."
*   **Integrate Security into User Stories/Requirements:** Define security requirements alongside functional requirements.
*   **Implement Plausibility Checks:** Validate business logic flows and data at each tier of the application.
*   **Write Secure Unit and Integration Tests:** Test critical security controls and business logic flows against identified threats.
*   **Segregate System Tiers:** Isolate components based on their exposure and protection needs (e.g., network segmentation, separate user roles).
*   **Limit Resource Consumption:** Design systems to handle resource requests safely and impose limits.
*   **Train Developers:** Educate developers on secure design principles and common pitfalls.