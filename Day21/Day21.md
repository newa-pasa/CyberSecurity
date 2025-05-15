 # Denial-of-Service (DoS) & DDoS Attacks
 
-- Types of DoS attacks (SYN Flood, UDP Flood, HTTP Flood)
-- Hands-on: Simulating & mitigating DoS attacks

**Denial-of-Service (DoS)** attacks aim to make a machine or network resource unavailable to its intended users by overwhelming it with a flood of illegitimate requests, disrupting normal traffic. A **Distributed Denial-of-Service (DDoS)** attack achieves the same goal but uses multiple compromised computer systems (often a botnet) as sources of attack traffic.

**Goal of DoS/DDoS:**
*   Disrupt service availability.
*   Cause financial loss to the target.
*   Distract security teams while other malicious activities occur.
*   Extortion or activism (hacktivism).

**Key Differences:**
*   **DoS:** Single attack source. Easier to trace and block.
*   **DDoS:** Multiple, distributed attack sources. Much harder to trace back to the actual attacker and significantly more difficult to mitigate due to the sheer volume and distributed nature of the traffic.

## Types of DoS attacks (SYN Flood, UDP Flood, HTTP Flood)

DoS/DDoS attacks can be broadly categorized based on the network layer they target:

**1. Volumetric Attacks (Bandwidth Depletion):**
   Aim to consume all available network bandwidth of the target.
   *   **UDP Flood:**
      *   **Mechanism:** The attacker sends a large number of User Datagram Protocol (UDP) packets to random ports on a target server.
      *   The server checks for applications listening at these ports.
      *   Finding none, it replies with an ICMP "Destination Unreachable" packet.
      *   If the volume of UDP packets is high, the server's resources (bandwidth, processing power) are consumed responding to these bogus requests, making it unavailable to legitimate traffic.
      *   **Impact:** Saturates network bandwidth, overwhelms network devices (firewalls, routers).
   *   **ICMP Flood (Ping Flood):**
      *   **Mechanism:** Overwhelms the target resource with ICMP Echo Request (ping) packets, generally sending packets as fast as possible without waiting for replies.
      *   The target attempts to respond with ICMP Echo Reply packets, consuming both outgoing and incoming bandwidth.
      *   **Impact:** Consumes bandwidth, can overwhelm the target's ability to process ICMP requests.
   *   **Other Spoofed-Packet Floods:** Attackers can send various types of spoofed packets to consume bandwidth.

**2. Protocol Attacks (Resource Depletion - State-Exhaustion):**
   Consume server resources or the resources of intermediate communication equipment (like firewalls and load balancers).
   *   **SYN Flood (TCP SYN Flood):**
      *   **Mechanism:** Exploits the TCP three-way handshake.
         1. Attacker sends a large volume of TCP SYN (synchronize) packets to the target server, often with spoofed source IP addresses.
         2. The server responds to each SYN packet with a SYN-ACK (synchronize-acknowledge) packet and opens a half-open connection, waiting for the client to complete the handshake with an ACK packet.
         3. Because the source IP is spoofed or the attacker simply doesn't send the final ACK, the server's connection queue (backlog) fills up with these half-open connections.
      *   **Impact:** Exhausts the server's connection state tables, preventing legitimate users from establishing new TCP connections.
   *   **Ping of Death (Historical):**
      *   **Mechanism:** Involved sending a malformed or oversized ICMP packet, which could crash older, unpatched systems.
      *   **Impact:** System crash. Mostly mitigated by modern OS.
   *   **Other Protocol Attacks:** Attacks targeting specific flaws in protocol implementations (e.g., Teardrop attacks - fragmented IP packets that couldn't be reassembled correctly).

**3. Application Layer Attacks (Resource Depletion - Application Level):**
   Target specific applications or services, often appearing as legitimate traffic, making them harder to detect.
   *   **HTTP Flood:**
      *   **Mechanism:** Attacker sends a high volume of seemingly legitimate HTTP GET or POST requests to a web server.
      *   These requests can be simple (requesting the homepage repeatedly) or complex (requesting resource-intensive scripts or database queries).
      *   The goal is to exhaust the server's resources (CPU, memory, database connections) that are used to process these requests.
      *   Often executed by botnets, making each request appear to come from a unique, legitimate user.
      *   **Impact:** Overwhelms the web server or application server, making it slow or unresponsive.
   *   **Slowloris:**
      *   **Mechanism:** The attacker opens multiple connections to a web server and keeps them alive by sending partial HTTP requests very slowly, but never completing them.
      *   The server keeps these connections open, waiting for the requests to complete.
      *   This gradually consumes all available connection slots in the server's connection pool, denying service to legitimate users.
      *   **Impact:** Exhausts server connection pool with minimal bandwidth from the attacker.
   *   **DNS Amplification/Reflection Attacks (Often used in DDoS):**
      *   **Mechanism:** Attacker sends DNS lookup requests to open DNS resolvers with the source IP spoofed to be the target's IP address. The requests are crafted to elicit a large response.
      *   The DNS resolvers send their large responses to the spoofed IP (the victim), overwhelming it.
      *   **Impact:** Amplifies the attack traffic significantly, saturates victim's bandwidth.

## Hands-on: Simulating & mitigating DoS attacks

**Disclaimer: Only perform these simulations on networks and systems you own or have explicit, written permission to test. Unauthorized DoS attacks are illegal and unethical.**

### Simulating DoS Attacks (Conceptual - Tools for Educational Use in a Lab):

1.  **Low Orbit Ion Cannon (LOIC) / High Orbit Ion Cannon (HOIC):**
    *   User-friendly tools often associated with hacktivist groups.
    *   Can perform HTTP, UDP, or TCP floods.
    *   **Caution:** Using these tools against any target without permission is illegal. For lab use only.

2.  **Hping3 (Linux command-line tool):**
    *   Versatile packet crafting tool.
    *   **SYN Flood Simulation:**
      ```bash
      # Target IP: 192.168.1.100, Target Port: 80
      # -S: SYN flag, -p 80: destination port 80
      # --flood: send packets as fast as possible
      # --rand-source: use random source IP addresses
      sudo hping3 -S -p 80 --flood --rand-source 192.168.1.100
      ```
    *   **UDP Flood Simulation:**
      ```bash
      # -2: UDP mode
      sudo hping3 -2 -p 53 --flood --rand-source 192.168.1.100
      ```

3.  **Python Scapy:**
    *   Powerful Python library for packet manipulation.
    *   Can craft custom packets for various DoS simulations.
    *   Example (Conceptual SYN flood):
      ```python
      from scapy.all import IP, TCP, send, RandIP
      target_ip = "192.168.1.100"
      target_port = 80
      # Craft IP and TCP layers
      ip_layer = IP(dst=target_ip, src=RandIP()) # Spoofed source
      tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S") # SYN packet
      packet = ip_layer/tcp_layer
      send(packet, loop=1, verbose=0) # Send in a loop
      ```

### Mitigating DoS/DDoS Attacks:

Mitigation strategies often involve a layered approach:

1.  **Traffic Scrubbing Centers / DDoS Mitigation Services:**
    *   Services like Cloudflare, AWS Shield, Akamai, Azure DDoS Protection.
    *   Route traffic through their networks where malicious traffic is filtered out before reaching your server.
    *   Use techniques like rate limiting, IP reputation filtering, challenge-response tests (e.g., CAPTCHAs), and signature-based detection.

2.  **Network Infrastructure:**
    *   **Firewalls & Intrusion Prevention Systems (IPS):**
        *   Configure rules to block known malicious IPs or anomalous traffic patterns.
        *   Stateful firewalls can help mitigate some protocol attacks.
        *   Web Application Firewalls (WAFs) are crucial for application-layer attacks, filtering based on HTTP/S traffic patterns.
    *   **Rate Limiting:** Configure routers, firewalls, or servers to limit the number of requests a single IP can make in a given time period.
    *   **Null Routing / Blackholing:** Drop all traffic to a targeted IP address at the network edge (ISP level or your own routers). This stops the attack but also makes the service unavailable.
    *   **SYN Cookies:** When the SYN queue fills up, the server sends a cryptographically generated cookie (SYN-ACK) instead of storing state. If a legitimate client responds, the server can reconstruct the connection.
    *   **Sufficient Bandwidth:** Over-provisioning bandwidth can help absorb smaller attacks.

3.  **Server/Application Hardening:**
    *   Optimize web servers and applications to handle connections efficiently.
    *   Keep systems patched to protect against protocol-level vulnerabilities.
    *   Implement connection limits per IP on the server.
    *   Use Content Delivery Networks (CDNs) to distribute content and absorb some traffic.

4.  **Incident Response Plan:**
    *   Have a plan in place for how to respond to a DoS/DDDoS attack.
    *   Know who to contact (ISP, mitigation service).
    *   Understand how to identify the type of attack to apply appropriate countermeasures.

5.  **Geoblocking:** Block traffic from geographic regions where you don't expect legitimate users.

**Detection:**
*   Monitoring network traffic volume, types of packets, connection tables.
*   Using SIEM systems to correlate logs and identify anomalies.
*   Performance degradation or unavailability of services.
