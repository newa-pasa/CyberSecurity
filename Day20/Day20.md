# Sniffing & Spoofing Attacks

Sniffing and spoofing are two fundamental types of network attacks that can lead to significant security breaches. They often go hand-in-hand, with spoofing enabling more effective sniffing or other attacks.

## Network Sniffing (Eavesdropping)
*   **Definition:** Network sniffing is the process of capturing, decoding, inspecting, and interpreting data packets that pass over a network. It's like tapping a phone line to listen in on conversations, but for network traffic.
*   **How it Works:**
    *   Network interfaces (NICs) are typically configured to only accept packets addressed to their own MAC address.
    *   In **promiscuous mode**, a NIC can be configured to accept all packets it sees on the network segment, regardless of the destination MAC address.
    *   Sniffing tools (e.g., Wireshark, tcpdump) put the NIC into promiscuous mode to capture this traffic.
*   **Types of Sniffing:**
    *   **Passive Sniffing:** Occurs on networks using hubs. Hubs broadcast all traffic to all ports, so an attacker can simply listen. This is less common now as switches have largely replaced hubs.
    *   **Active Sniffing:** Required on switched networks. Switches learn which MAC address is on which port and only forward traffic to the correct port. Active sniffing involves techniques to redirect traffic to the attacker's machine, such as ARP spoofing, MAC flooding, or DNS spoofing.
*   **Information Gathered:**
    *   Usernames and passwords (if transmitted in clear text, e.g., old FTP, Telnet, unencrypted HTTP).
    *   Email contents.
    *   Files being transferred.
    *   Websites visited.
    *   Sensitive configuration data.
*   **Impact:**
    *   Data theft and confidentiality breaches.
    *   Credential harvesting.
    *   Reconnaissance for further attacks.
*   **Tools:** Wireshark, tcpdump, ngrep, dsniff suite.
*   **Countermeasures:**
    *   **Encryption:** Use HTTPS, SSH, VPNs, TLS/SSL to encrypt data in transit.
    *   **Switched Networks:** Use switches instead of hubs.
    *   **Network Segmentation:** Limit the broadcast domain.
    *   **Intrusion Detection Systems (IDS):** Can sometimes detect sniffing activities or anomalies caused by active sniffing techniques.
    *   **Port Security:** On switches, can limit the number of MAC addresses per port or bind specific MAC addresses to ports.

## Network Spoofing
*   **Definition:** Spoofing is the act of disguising a communication from an unknown source as being from a known, trusted source. It involves faking some part of network communication, like an IP address, MAC address, or email sender.
*   **Types of Spoofing:**
    *   **IP Spoofing:** Creating IP packets with a forged source IP address to impersonate another system or to hide the sender's identity. Often used in DoS attacks.
    *   **MAC Spoofing:** Changing the MAC address of a network interface to impersonate another device. Can be used to bypass MAC filtering or in conjunction with ARP spoofing.
    *   **ARP Spoofing:** (Covered in detail below) Sending forged ARP messages onto a LAN.
    *   **DNS Spoofing (DNS Cache Poisoning):** Modifying DNS records to redirect traffic to a malicious site.
    *   **Email Spoofing:** Forging the sender address in an email.
    *   **Web Spoofing (Phishing):** Creating a fake website that looks like a legitimate one to steal credentials.
*   **Impact:**
    *   Bypassing access controls.
    *   Man-in-the-Middle attacks.
    *   Denial of Service (DoS) attacks.
    *   Spreading malware.
    *   Identity theft.
*   **Countermeasures:**
    *   **Ingress/Egress Filtering:** Routers can filter packets with source IP addresses that are not valid for the network segment they originate from.
    *   **Cryptographic Authentication:** Using digital signatures and certificates to verify the authenticity of senders and servers (e.g., HTTPS, DKIM for email).
    *   **ARP Spoofing Detection Tools:** Tools that monitor ARP traffic for anomalies.
    *   **Dynamic ARP Inspection (DAI):** A security feature on switches that validates ARP packets.

## ARP Spoofing & MITM (Man-In-The-Middle) attacks

**ARP (Address Resolution Protocol)**
*   **Purpose:** ARP is used to map an IP address (Layer 3) to a MAC address (Layer 2) within a local area network (LAN).
*   **How it Works:**
    1.  When Host A wants to send data to Host B on the same LAN but only knows Host B's IP address, Host A broadcasts an "ARP Request" saying, "Who has IP address [IP_B]? Tell [MAC_A]."
    2.  Host B receives this broadcast and replies directly to Host A with an "ARP Reply" saying, "[IP_B] is at [MAC_B]."
    3.  Host A caches this IP-to-MAC mapping in its ARP table for future use.
*   **Stateless Nature:** ARP is stateless. Devices will typically accept ARP replies even if they didn't send an ARP request. This is a key vulnerability.

**ARP Spoofing (ARP Poisoning)**
*   **Definition:** An attack where a malicious actor sends forged ARP messages onto a LAN. The goal is to associate the attacker's MAC address with the IP address of another host (like the default gateway or another client).
*   **Mechanism:**
    1.  The attacker sends unsolicited ARP replies to the target machine(s).
    2.  **Example 1 (Targeting a Client):** Attacker sends an ARP reply to Client A, claiming that the Gateway's IP address now maps to the Attacker's MAC address.
    3.  **Example 2 (Targeting the Gateway):** Attacker sends an ARP reply to the Gateway, claiming that Client A's IP address now maps to the Attacker's MAC address.
    4.  The victims update their ARP caches with the false information.
*   **Result:** All traffic from Client A intended for the Gateway (and thus the internet) is sent to the Attacker. If the gateway is also poisoned, traffic from the Gateway intended for Client A is also sent to the Attacker.

**Man-in-the-Middle (MITM) Attack via ARP Spoofing**
*   **Definition:** Once ARP spoofing is successful, the attacker is positioned "in the middle" of the communication between two (or more) parties.
*   **How it Works (with ARP Spoofing):**
    1.  Attacker performs ARP spoofing against both a target client and the default gateway.
    2.  Client's traffic to the internet goes to the attacker.
    3.  Gateway's traffic to the client goes to the attacker.
    4.  The attacker can then:
        *   **Sniff:** Read all the traffic (passwords, sensitive data if unencrypted).
        *   **Modify:** Alter data in transit (e.g., change download links, inject malicious code into web pages).
        *   **Block/Drop:** Selectively deny service.
    5.  To maintain connectivity and remain undetected, the attacker usually enables IP forwarding on their machine, so legitimate traffic is passed on to its intended destination after being inspected or modified.
*   **Impact:**
    *   Complete compromise of data confidentiality and integrity for unencrypted traffic.
    *   Session hijacking.
    *   Credential theft.
    *   Malware injection.
*   **Detection:**
    *   ARP monitoring tools (e.g., `arpwatch`, XArp) can detect suspicious ARP activity.
    *   Checking ARP tables for duplicate MAC addresses associated with different IPs, or an IP associated with an unexpected MAC.
    *   Network latency or unusual connectivity issues.
*   **Prevention/Mitigation:**
    *   **Dynamic ARP Inspection (DAI):** A Cisco switch feature that validates ARP packets by checking them against a trusted database of IP-MAC bindings (often built from DHCP snooping).
    *   **Static ARP Entries:** Manually configuring ARP entries on critical hosts. This is often impractical for large networks.
    *   **Port Security:** Can help, but MAC spoofing can bypass simple port security.
    *   **IDS/IPS:** May detect ARP spoofing attempts.
    *   **End-to-End Encryption (HTTPS, VPNs):** Even if an MITM attack occurs, encrypted data remains confidential. This is the most robust defense against the *consequences* of MITM.

## Hands-on: Using Ettercap for ARP spoofing

**Ettercap** is a comprehensive suite for man-in-the-middle attacks on LAN. It features sniffing of live connections, content filtering on the fly, and many other interesting tricks. It supports active and passive dissection of many protocols and includes facilities for network and host analysis.

**Disclaimer: Only perform these actions on networks you own or have explicit permission to test. Unauthorized network attacks are illegal and unethical.**

**General Workflow (Conceptual - specific commands vary slightly by Ettercap version/mode):**

1.  **Prerequisites:**
    *   Kali Linux (or another Linux distribution with Ettercap installed).
    *   Root privileges.
    *   Network interface connected to the target LAN.

2.  **Launch Ettercap:**
    *   Typically launched from the terminal: `sudo ettercap -G` (for GUI) or `sudo ettercap -T -q` (for text mode).
    *   `-G`: Graphical interface.
    *   `-T`: Text-based interface.
    *   `-q`: Quiet mode (less verbose output in text mode).

3.  **Select Network Interface:**
    *   In the GUI: `Sniff` -> `Unified sniffing...` -> Select your network interface (e.g., `eth0`, `wlan0`).
    *   In text mode, it often defaults or can be specified with the `-i` flag: `sudo ettercap -T -q -i eth0 ...`

4.  **Scan for Hosts:**
    *   GUI: `Hosts` -> `Scan for hosts`. Ettercap will send ARP requests to discover live hosts on the network.
    *   GUI: `Hosts` -> `Hosts list` to view discovered hosts.

5.  **Select Targets:**
    *   Identify the IP address of your target client(s) and the default gateway.
    *   GUI: In the `Hosts list`, select the client's IP and click `Add to Target 1`. Select the gateway's IP and click `Add to Target 2`.
    *   Text Mode: Targets are often specified with `-M arp /TARGET1_IP/ /TARGET2_IP/`. For example, `/192.168.1.10/ /192.168.1.1/` where `.10` is the client and `.1` is the gateway. If you want to poison all hosts to redirect to you instead of the gateway, you might use `/CLIENT_IP_RANGE/ /GATEWAY_IP/` or just target the gateway and one client.

6.  **Start ARP Spoofing Attack:**
    *   GUI: `Mitm` -> `Arp poisoning...` -> Check `Sniff remote connections` -> Click `OK`.
    *   Text Mode: The `-M arp` option initiates ARP poisoning. Example: `sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.101/ /192.168.1.1/`
        *   `:remote` tells Ettercap to poison both targets to redirect traffic through the attacker.
        *   `:oneway` would poison only Target 1 to redirect its traffic for Target 2 to the attacker.

7.  **Enable IP Forwarding (Crucial for MITM):**
    *   The attacker's machine must forward the intercepted packets to their intended destinations to maintain connectivity and avoid immediate detection.
    *   Ettercap often handles this automatically when ARP poisoning is active.
    *   You can also manually enable it on Linux: `echo 1 > /proc/sys/net/ipv4/ip_forward`

8.  **Sniff/Manipulate Traffic:**
    *   Once ARP spoofing is active, Ettercap will start capturing traffic between Target 1 and Target 2.
    *   GUI: `View` -> `Connections` to see active connections. You can inspect data.
    *   Ettercap has plugins (e.g., `dns_spoof`, `sslstrip` - though `sslstrip` is less effective against HSTS) that can be used to manipulate traffic.
    *   You can also run a separate sniffer like Wireshark on the attacker's machine to capture and analyze the intercepted traffic in more detail.

9.  **Stop the Attack:**
    *   GUI: `Mitm` -> `Stop mitm attack(s)`.
    *   Text Mode: Press `q` to quit Ettercap.
    *   Ettercap *should* send corrective ARP packets to restore the victims' ARP tables.
    *   Disable IP forwarding if manually enabled: `echo 0 > /proc/sys/net/ipv4/ip_forward`

**Important Considerations with Ettercap:**
*   **Legality and Ethics:** Reiterate the importance of authorized testing.
*   **Network Disruption:** Incorrectly configured or abruptly stopped attacks can disrupt network connectivity for the targets.
*   **SSL/TLS:** Modern HTTPS (with HSTS) makes simple sniffing of encrypted content very difficult. Attacks like SSL stripping (trying to downgrade HTTPS to HTTP) are less effective now but still a concept to understand. More advanced MITM might involve fake certificates, which browsers are good at warning about.
*   **Detection:** ARP spoofing can be detected.

This provides a solid foundation for understanding these attacks and how a tool like Ettercap facilitates them.