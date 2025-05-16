# Footprinting & Reconnaissance Techniques

*   **Definition:** The initial phase in the ethical hacking process (and malicious attacks). It involves systematically gathering information about a target organization, its systems, networks, employees, and security posture.
*   **Goal:** To build a comprehensive profile of the target, identify potential entry points, understand the attack surface, and plan subsequent phases of an attack or penetration test.
*   **Importance:**
    *   Identifies potential vulnerabilities.
    *   Maps the network infrastructure (IP ranges, domains, subdomains).
    *   Discovers technologies used (web servers, OS, applications).
    *   Uncovers organizational details (employee names, emails, roles, locations).
    *   Reduces the chances of detection during later, more intrusive phases.
    *   Forms the foundation for a successful penetration test.

## Passive & Active Footprinting

### Passive Footprinting
*   **Definition:** Gathering information about a target *without* directly interacting with the target's systems or network. Relies on publicly available information (OSINT).
*   **Characteristics:**
    *   **Stealthy:** Very low risk of detection by the target organization.
    *   **Indirect:** Uses third-party sources and public records.
*   **Common Techniques & Sources:**
    *   **OSINT (Open Source Intelligence):** Leveraging publicly accessible data.
    *   **Company Website Analysis:** Reviewing `About Us`, `Careers`, `Contact`, `News/Press Releases`, source code comments, metadata in documents.
    *   **Search Engines:** Using Google, Bing, DuckDuckGo (including advanced operators - see Google Dorking).
    *   **Social Media:** Monitoring platforms like LinkedIn (employee details, roles, technologies), Twitter, Facebook.
    *   **Job Postings:** Revealing technologies used, team structures, internal project names.
    *   **Public Records:** Whois databases (domain registration details), DNS records (A, MX, NS, TXT), financial reports, government filings.
    *   **Specialized Search Engines:** Shodan (IoT/ICS devices), Censys.
    *   **Online Communities & Forums:** Developer forums, mailing lists where employees might participate.
    *   **News Articles & Archives:** Information about partnerships, acquisitions, past security incidents.

### Active Footprinting
*   **Definition:** Gathering information by directly interacting with the target's systems, network, or personnel.
*   **Characteristics:**
    *   **Direct Interaction:** Involves sending packets, probes, or queries to the target.
    *   **Higher Risk of Detection:** Activities can be logged by firewalls, Intrusion Detection Systems (IDS), or Intrusion Prevention Systems (IPS).
    *   **More Detailed Information:** Can reveal specific technical details not available publicly.
*   **Common Techniques:**
    *   **Port Scanning:** Identifying open TCP/UDP ports and services running on target hosts (e.g., using Nmap).
    *   **Network Scanning/Mapping:** Discovering live hosts, network topology, and operating systems within a target network range.
    *   **Banner Grabbing:** Retrieving service banners (e.g., web server version, SSH version) by connecting to open ports.
    *   **Website Probing:** Identifying web server types, technologies (e.g., CMS like WordPress, Drupal), directory structures, hidden files.
    *   **DNS Zone Transfers (if misconfigured):** Attempting to retrieve all DNS records for a domain directly from the DNS server.
    *   **Traceroute/Path Analysis:** Mapping the network path to a target host.
    *   **Email Harvesting (Active):** Sending test emails to guessed addresses to see if they bounce.
    *   **Social Engineering (e.g., Phishing):** Directly interacting with employees to elicit information (use with extreme caution and only within agreed scope).

## Hands-on: Using OSINT tools (Google Dorking, Shodan, Maltego)

### OSINT (Open Source Intelligence)
*   Leveraging publicly available information is the cornerstone of passive footprinting. The tools below are key examples of OSINT techniques.

### Google Dorking (Google Hacking)
*   **What it is:** Using advanced search operators in Google (and other search engines) to find specific information that may not be intended for public view but has been indexed.
*   **Purpose:** Uncover sensitive files, login pages, configuration details, vulnerable web applications, company information, etc.
*   **Common Operators (Dorks):**
    *   `site:[domain.com]`: Restricts search to a specific website. (e.g., `site:target.com admin`)
    *   `filetype:[ext]`: Searches for specific file types. (e.g., `site:target.com filetype:pdf confidential`)
    *   `inurl:[text]`: Searches for specific text within URLs. (e.g., `inurl:login`, `inurl:/admin/`)
    *   `intitle:[text]`: Searches for specific text within page titles. (e.g., `intitle:"index of /" "backup"`)
    *   `intext:[text]`: Searches for specific text within the page content. (e.g., `intext:"password" filetype:log`)
    *   `cache:[URL]`: Shows Google's cached version of a page.
    *   `related:[URL]`: Finds sites similar to the specified URL.
*   **Example Combination:** `site:target.com filetype:xls intext:username`

### Shodan (www.shodan.io)
*   **What it is:** A search engine specifically designed to find internet-connected devices (servers, webcams, routers, IoT devices, industrial control systems). It scans the internet and indexes service banners.
*   **Purpose:** Discover exposed devices, identify running services and versions, find default credentials, locate specific technologies or vulnerable systems associated with a target.
*   **Common Search Filters:**
    *   `hostname:[domain]`: Find devices associated with a domain. (e.g., `hostname:target.com`)
    *   `org:"Organization Name"`: Find devices belonging to a specific organization. (e.g., `org:"Target Inc."`)
    *   `net:[IP/CIDR]`: Search within a specific IP range. (e.g., `net:192.168.1.0/24`)
    *   `port:[number]`: Find devices with a specific port open. (e.g., `port:22`, `port:3389`)
    *   `product:"Product Name"`: Search for specific software/hardware. (e.g., `product:"Apache httpd"`)
    *   `country:"XX"`, `city:"City Name"`: Filter by location.
*   **Example Use:** Finding exposed RDP ports (`port:3389 org:"Target Inc."`) or webcams (`webcam`).

### Maltego
*   **What it is:** An interactive data mining and visualization tool for OSINT and forensics. It gathers information from diverse public sources (DNS records, Whois, search engines, social networks, etc.) and represents it as a graph.
*   **Purpose:** To discover relationships and links between disparate pieces of information like domains, IP addresses, organizations, people, email addresses, phone numbers, social media profiles, files, etc.
*   **How it Works:**
    *   Uses "Transforms" to query various data sources.
    *   Starts with a known piece of information (e.g., a domain name, an email address).
    *   Runs transforms to find related entities.
    *   Visualizes the results as a graph, showing connections.
*   **Use Cases in Footprinting:** Mapping domain infrastructure, finding associated email addresses and personnel, discovering related social media profiles, visualizing network blocks.