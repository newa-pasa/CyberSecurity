# Scanning & Enumeration Techniques

## Network scanning basics

### a. Definition & Purpose

*   **Network Scanning:** The process of probing a computer network to discover active hosts, open ports, running services, and potentially other characteristics like operating systems or vulnerabilities.
*   **Purpose (Attacker Perspective):** Reconnaissance phase. Identify potential targets, understand the network layout, find entry points (open ports, vulnerable services), and gather information for exploitation.
*   **Purpose (Defender Perspective):** Network mapping, security auditing, inventory management, vulnerability assessment, verifying firewall rules, and ensuring only authorized services are running.

### b. Key Information Gathered

*   **Live Hosts:** Identifying which IP addresses on the network are active and responding.
*   **Open Ports:** Determining which TCP and UDP ports are listening for incoming connections on active hosts. Each open port usually corresponds to a specific network service.
*   **Services:** Identifying the specific software (e.g., Apache web server, OpenSSH server, Microsoft SQL Server) running on open ports.
*   **Service Versions:** Determining the exact version of the software running on a service. This is crucial for identifying known vulnerabilities.
*   **Operating System (OS):** Estimating the operating system running on the target host based on its network behavior (TCP/IP stack fingerprinting).
*   **Firewall Detection:** Inferring the presence and sometimes the ruleset of firewalls by observing which probes are blocked or how the target responds.

### c. Core Scanning Techniques

1.  **Host Discovery (Ping Sweeps):**
    *   **Goal:** Find live hosts within a target IP range.
    *   **Methods:**
        *   **ICMP Echo Request (Ping):** Sends ICMP Type 8 message, expects ICMP Type 0 reply. Often blocked by firewalls.
        *   **TCP SYN Ping:** Sends a SYN packet to a common port (e.g., 80, 443). A SYN/ACK response indicates the host is up (port state doesn't matter here, just host response). RST response also indicates host is up. More likely to bypass firewalls than ICMP.
        *   **TCP ACK Ping:** Sends an ACK packet. A RST response indicates the host is up (as per RFC, hosts should send RST for unsolicited ACKs). Can sometimes bypass stateless firewalls.
        *   **UDP Ping:** Sends a UDP packet to a specific port (often an unlikely one). If the host is up and the port is closed, it *should* return an ICMP "Port Unreachable" message. Lack of response is ambiguous (host down, firewall, packet loss).
    *   **Tools:** `nmap -sn`, `ping`, custom scripts.

2.  **Port Scanning:**
    *   **Goal:** Identify open TCP and UDP ports on a *known* live host.
    *   **Common TCP Scan Types:**
        *   **TCP Connect Scan (`-sT` in Nmap):** Completes the full TCP three-way handshake (SYN -> SYN/ACK -> ACK). Reliable but easily detectable and logged by applications. Doesn't require special privileges.
        *   **TCP SYN Scan (`-sS` in Nmap, "Stealth Scan"):** Sends SYN, receives SYN/ACK (port open) or RST (port closed). If SYN/ACK is received, sends RST instead of ACK to tear down the connection before completion. Faster and less likely to be logged by *applications* (but easily detected by firewalls/IDS). Requires raw socket privileges (usually root/administrator). *Default Nmap scan type with sufficient privileges.*
        *   **FIN/NULL/Xmas Scans (`-sF`, `-sN`, `-sX` in Nmap):** Send packets with only FIN, no flags, or FIN+PSH+URG flags set, respectively. Rely on RFC 793 quirk: closed ports should respond with RST, open ports should ignore these packets. Stealthy against *some* non-RFC compliant systems or stateless firewalls. Unreliable, especially against Windows. Require raw socket privileges.
    *   **UDP Scan (`-sU` in Nmap):**
        *   Sends a UDP packet to the target port.
        *   **Open:** No response (common), or a service-specific UDP response.
        *   **Closed:** ICMP "Port Unreachable" (Type 3, Code 3) message received.
        *   **Filtered:** Other ICMP unreachable errors (e.g., Type 3, Code 1, 2, 9, 10, 13) or no response after retransmissions.
        *   **Challenges:** UDP is connectionless, making scanning slow and potentially unreliable due to packet loss, rate limiting, and firewall rules.

3.  **Service Version Detection (`-sV` in Nmap):**
    *   **Goal:** Determine the application name and version running on an open port.
    *   **Method:** Sends specific probes tailored to different protocols after discovering an open port. Analyzes the responses (banners, protocol-specific replies) against a database (`nmap-service-probes`).
    *   **Importance:** Essential for vulnerability assessment, as exploits are often version-specific.

4.  **OS Detection (`-O` in Nmap):**
    *   **Goal:** Guess the operating system of the target.
    *   **Method:** Sends a series of TCP, UDP, and ICMP probes targeting both open and closed ports. Analyzes subtle differences in the TCP/IP stack implementation (e.g., initial window size, TTL, TCP options, IP ID sequence generation, ICMP responses). Compares the resulting "fingerprint" against a database (`nmap-os-db`).
    *   **Requirements:** Usually needs at least one open and one closed TCP port for reliable results. Requires raw socket privileges.

### d. Ethical Considerations & Legality

*   **Authorization is MANDATORY:** Performing network scanning on any network or system you do not have explicit, written permission to scan is illegal and unethical.
*   **Potential Impact:** Aggressive scanning can potentially disrupt services or trigger security alerts. Always understand the potential impact of your scans.
*   **Scope:** Strictly adhere to the agreed-upon scope when performing authorized scans.

---

## Hands-on: Using Nmap & Netcat for scanning

### a. Nmap (Network Mapper)

*   **Description:** The industry-standard, powerful, and versatile open-source tool for network discovery and security auditing.
*   **Key Features:** Host discovery, port scanning (various types), service/version detection, OS detection, scriptable interaction via Nmap Scripting Engine (NSE).

*   **Common Nmap Commands & Options:**

    *   **Target Specification:**
        *   Single IP: `nmap 192.168.1.1`
        *   Hostname: `nmap scanme.nmap.org`
        *   Range: `nmap 192.168.1.1-100`
        *   CIDR block: `nmap 192.168.1.0/24`
        *   From a file: `nmap -iL targets.txt`

    *   **Host Discovery (Ping Scan):**
        *   `nmap -sn 192.168.1.0/24` (Disables port scan, only finds live hosts)
        *   `nmap -Pn 192.168.1.1` (Skip host discovery, assume host is up - useful if ping is blocked)

    *   **Port Scanning:**
        *   `nmap 192.168.1.1` (Default: SYN scan if root, Connect scan otherwise, scans top 1000 TCP ports)
        *   `nmap -p 80,443,8080 192.168.1.1` (Scan specific ports)
        *   `nmap -p 1-1024 192.168.1.1` (Scan a range of ports)
        *   `nmap -p- 192.168.1.1` (Scan all 65535 TCP ports)
        *   `nmap -F 192.168.1.1` (Fast scan - scans fewer ports than default, top 100)

    *   **Scan Types:**
        *   `nmap -sS 192.168.1.1` (TCP SYN Scan - requires root/admin)
        *   `nmap -sT 192.168.1.1` (TCP Connect Scan)
        *   `nmap -sU 192.168.1.1` (UDP Scan - often slow, combine with `-p`)
        *   `nmap -sU -p 53,161,162 192.168.1.1` (Scan specific UDP ports)
        *   `nmap -sF 192.168.1.1` (FIN Scan - requires root/admin)

    *   **Service & OS Detection:**
        *   `nmap -sV 192.168.1.1` (Detect service versions on open ports)
        *   `nmap -O 192.168.1.1` (Enable OS detection - requires root/admin)
        *   `nmap -A 192.168.1.1` (Aggressive: Enables OS detection (`-O`), version detection (`-sV`), script scanning (`-sC`), and traceroute (`--traceroute`))

    *   **Timing & Performance:**
        *   `nmap -T4 192.168.1.1` (Set timing template - T0=paranoid, T1=sneaky, T2=polite, T3=normal (default), T4=aggressive, T5=insane. T4 is common for faster scans on good networks.)
        *   `--min-rate 1000` (Send packets no slower than 1000 per second)

    *   **Output Formats:**
        *   `nmap -oN output.txt 192.168.1.1` (Normal output)
        *   `nmap -oG output.grep 192.168.1.1` (Grepable output)
        *   `nmap -oX output.xml 192.168.1.1` (XML output)
        *   `nmap -oA output_basename 192.168.1.1` (Output in all major formats: .nmap, .gnmap, .xml)

    *   **Nmap Scripting Engine (NSE):**
        *   `nmap -sC 192.168.1.1` (Run default safe scripts)
        *   `nmap --script=vuln 192.168.1.1` (Run scripts in the 'vuln' category)
        *   `nmap --script=http-title 192.168.1.1 -p 80,443` (Run a specific script)

### b. Netcat (nc)

*   **Description:** A versatile networking utility for reading from and writing to network connections using TCP or UDP. Often called the "Swiss Army knife" of networking. Useful for simple port checks, banner grabbing, and manual service interaction.
*   **Key Features:** Can act as a client or server, supports TCP and UDP, port scanning (basic), data transfer, network debugging.

*   **Common Netcat Commands & Options for Scanning:**

    *   **Basic TCP Port Check (Connect Scan):**
        *   `nc -nv -w 1 -z 192.168.1.1 80`
            *   `-n`: Numeric only (don't resolve DNS).
            *   `-v`: Verbose (provides feedback).
            *   `-w 1`: Wait timeout (e.g., 1 second). Crucial for scripting.
            *   `-z`: Zero-I/O mode (report connection status without sending data).
        *   Example: Check if port 80 is open on `192.168.1.1`. Output like "Connection to 192.168.1.1 80 port [tcp/http] succeeded!" indicates open.

    *   **Basic UDP Port Check:**
        *   `nc -nv -u -w 1 -z 192.168.1.1 53`
            *   `-u`: Use UDP instead of TCP.
        *   **Note:** UDP scanning with `nc -z` is often unreliable. It might report success even if the port is closed/filtered because it doesn't wait for the ICMP "Port Unreachable" that signifies a closed port in UDP scanning. Sending data is often better: `echo "TEST" | nc -u -w 1 192.168.1.1 53`.

    *   **Scanning a Range of Ports (using shell loop):**
        *   Bash example to check TCP ports 1-100 and show only open ones:
          ```bash
          for port in {1..100}; do nc -nv -w 1 -z 192.168.1.1 $port 2>&1 | grep succeeded; done
          ```

    *   **Banner Grabbing (Service Identification):**
        *   Connect to an open port and see the initial response from the service.
        *   `nc -nv 192.168.1.1 22` (Connect to SSH port 22, should show SSH version banner).
        *   `nc -nv 192.168.1.1 25` (Connect to SMTP port 25, should show mail server greeting).
        *   Connect to HTTP port 80, send a basic HTTP request, and print the response including server headers:
          ```bash
          echo -e "GET / HTTP/1.0\r\n\r\n" | nc -nv -w 2 192.168.1.1 80
          ```
          *(Note: Use `echo -e` in Bash or similar for `\r\n` interpretation)*

    *   **Limitations vs. Nmap:**
        *   Much slower for scanning large ranges.
        *   No built-in advanced features like OS detection, comprehensive version detection, or scriptable checks.
        *   Less sophisticated handling of different network conditions and target responses.
        *   Primarily useful for quick checks, manual interaction, and scripting simple tasks.

