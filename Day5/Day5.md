# Hands-on Lab: Wireshark for Network Traffic Analysis

## Introduction to Wireshark

Wireshark is the world's foremost and widely-used network protocol analyzer. It lets you see what's happening on your network at a microscopic level and is the de facto (and often de jure) standard across many commercial and non-profit enterprises, government agencies, and educational institutions.

**Why Use Wireshark?**

*   **Network Troubleshooting:** Identify connectivity issues, latency problems, configuration errors.
*   **Security Analysis:** Detect suspicious activities, analyze malware traffic, investigate security incidents, identify policy violations.
*   **Protocol Learning:** Understand how network protocols work in practice (TCP handshake, DNS lookups, HTTP requests, etc.).
*   **Software Development:** Debug network applications.

**Key Features:**

*   Deep inspection of hundreds of protocols.
*   Live capture and offline analysis.
*   Rich VoIP analysis.
*   Runs on Windows, Linux, macOS, Solaris, FreeBSD, NetBSD, and others.
*   Captured network data can be browsed via a GUI, or via the TTY-mode `tshark` utility.
*   Powerful display filters.
*   Coloring rules for quick, intuitive analysis.

## Getting Started with Wireshark

### Installation

*   Often pre-installed on security-focused Linux distributions like Kali Linux.
*   Downloadable from the official website (https://www.wireshark.org) for various operating systems.
*   Installation typically includes `Npcap` (on Windows) or relies on `libpcap` (on Linux/macOS) for packet capture libraries.

### Selecting the Network Interface

*   Upon starting Wireshark, you'll see a list of available network interfaces (e.g., `eth0` for Ethernet, `wlan0` for Wireless).
*   You **must** select the interface through which the traffic you want to analyze is flowing. Double-clicking the interface name usually starts the capture.
*   **Promiscuous Mode:** Ensure this mode is enabled (usually default and requires administrator/root privileges). It allows the network interface to capture *all* packets it sees on the network segment, not just those addressed to its own MAC address. Without it, you'll miss most traffic on switched networks.

### The Wireshark Interface

The default interface is typically divided into three main panes:

1.  **Packet List Pane:** Displays a summary of each captured packet. Columns include:
    *   `No.`: Packet number in the capture file.
    *   `Time`: Timestamp of when the packet was captured.
    *   `Source`: Source IP address (or MAC if not IP).
    *   `Destination`: Destination IP address (or MAC).
    *   `Protocol`: Highest-level protocol identified (e.g., HTTP, DNS, TCP, ARP).
    *   `Length`: Total length of the packet in bytes.
    *   `Info`: Summary details about the packet's content (e.g., HTTP GET request details, TCP flags, DNS query info).
2.  **Packet Details Pane:** Shows the protocol layers of the currently selected packet in an expandable tree view. This allows deep inspection:
    *   `Frame`: Physical layer details (capture time, length).
    *   `Ethernet`: Data link layer (Source/Destination MAC addresses).
    *   `Internet Protocol (IP)`: Network layer (Source/Destination IP addresses, TTL, etc.).
    *   `Transmission Control Protocol (TCP)` or `User Datagram Protocol (UDP)`: Transport layer (Source/Destination ports, sequence/acknowledgment numbers, flags (TCP), checksums).
    *   `Application Layer Protocol`: (e.g., HTTP, DNS, SMB) - The actual data payload details.
3.  **Packet Bytes Pane:** Displays the raw data of the selected packet in hexadecimal and ASCII format. Useful for identifying specific data patterns or analyzing protocols Wireshark doesn't fully dissect.

## Capturing Network Packets

1.  **Select Interface(s):** Choose one or more network interfaces to capture from.
2.  **Start Capture:** Click the blue shark fin icon (Start capturing packets) or select `Capture > Start`.
3.  **Generate Traffic:** Perform the network activity you want to analyze (browse a website, ping a host, run an application).
4.  **Stop Capture:** Click the red square icon (Stop capturing packets) or select `Capture > Stop`. Capturing generates data quickly, so stop when you have what you need.
5.  **Save Capture:** Save the captured data (`File > Save As...`) to a `.pcapng` (preferred) or `.pcap` file for later analysis.

### Capture Filters (BPF Syntax)

*   Applied *before* capturing starts. They limit *what* packets are captured and saved, reducing file size and focusing the capture.
*   Use Berkeley Packet Filter (BPF) syntax (different from display filters).
*   Entered in the "Capture filter" field near the interface list.
*   **Examples:**
    *   `host 192.168.1.100`: Capture traffic to or from this IP address.
    *   `src host 192.168.1.100`: Capture traffic *from* this IP.
    *   `dst host 192.168.1.100`: Capture traffic *to* this IP.
    *   `net 192.168.1.0/24`: Capture traffic involving this subnet.
    *   `port 80`: Capture traffic using source or destination port 80 (HTTP).
    *   `tcp port 22`: Capture TCP traffic on port 22 (SSH).
    *   `udp port 53`: Capture UDP traffic on port 53 (DNS).
    *   `host 192.168.1.100 and port 80`: Capture HTTP traffic involving the host.
    *   `not arp`: Capture everything except ARP packets.

## Analyzing Network Packets

### Display Filters

*   Applied *after* capture (or when loading a file). They **hide** packets from view without deleting them, making analysis manageable.
*   Entered in the "Apply a display filter" bar at the top. The bar turns green for valid syntax, red for invalid.
*   Wireshark has a powerful and intuitive filtering language.
*   **Common Examples:**
    *   **By Protocol:** `http`, `dns`, `icmp`, `arp`, `tcp`, `udp`, `smtp`, `ftp`, `smb`
    *   **By IP Address:**
        *   `ip.addr == 192.168.1.1` (Source or Destination)
        *   `ip.src == 192.168.1.1`
        *   `ip.dst == 10.0.0.5`
    *   **By Port Number:**
        *   `tcp.port == 443` (Source or Destination)
        *   `udp.port == 53`
        *   `tcp.srcport == 1025`
        *   `tcp.dstport == 80`
    *   **By MAC Address:** `eth.addr == 00:11:22:33:44:55`
    *   **Combining Filters (Logical Operators):**
        *   `and` (or `&&`): `ip.addr == 192.168.1.1 and tcp.port == 80`
        *   `or` (or `||`): `dns or http`
        *   `not` (or `!`): `not arp`
    *   **Specific Protocol Fields:**
        *   `http.request.method == "POST"`
        *   `dns.qry.name == "example.com"`
        *   `tcp.flags.syn == 1` (Packets with SYN flag set)
        *   `tcp.flags.reset == 1` (Packets with RST flag set)
        *   `ftp.request.command == "USER"`
    *   **Contains Operator:** `frame contains "password"` (Searches raw packet bytes - can be slow)

### Following Conversations (Streams)

*   Essential for understanding application-level data exchange.
*   Right-click a packet belonging to a conversation (TCP, UDP, HTTP, TLS, etc.) and select `Follow > [Protocol] Stream` (e.g., `Follow > TCP Stream`).
*   Opens a new window showing the reconstructed data flow between the client and server in a readable format.
*   Crucial for analyzing unencrypted protocols like HTTP, FTP, Telnet to see usernames, passwords, commands, transferred data.
*   Even for encrypted streams (like TLS/HTTPS), following the stream can show the initial handshake details.

## Identifying Suspicious Network Activities

Wireshark is invaluable for detecting potential security issues by observing network traffic patterns.

### Examples of Suspicious Activities & Filters:

1.  **Network Scanning:**
    *   **SYN Scan (Stealth Scan):** Attacker sends SYN packets to various ports. Open ports reply with SYN/ACK, closed ports reply with RST/ACK. Attacker sends RST to tear down connection before completion.
        *   *Filter:* `tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == [attacker_ip]` (Look for many such packets to different ports on a target).
        *   *Filter:* `tcp.flags.reset == 1` (Look for many RST packets from the target in response).
    *   **Port Scanning (General):** A single source IP connecting to many different destination ports on one or more target hosts in a short period.
        *   *Analysis:* Use `Statistics > Conversations`, sort by packets or duration from a suspected scanner IP. Look for many connections with few packets each.
    *   **Host Discovery (Ping Sweep):** ICMP Echo Requests sent to multiple hosts on a network.
        *   *Filter:* `icmp.type == 8` (Echo Request) - Look for requests from one source to many destinations.

2.  **Unencrypted Credentials:**
    *   **HTTP Basic Auth / POST Requests:** Login forms submitted over plain HTTP.
        *   *Filter:* `http.request.method == "POST"` or `http.authorization`
        *   *Analysis:* Follow TCP/HTTP stream on relevant packets. Look for `Authorization: Basic [base64_string]` or form data like `username=...&password=...`.
    *   **FTP:** Login credentials sent in plain text.
        *   *Filter:* `ftp`
        *   *Analysis:* Follow TCP stream. Look for `USER` and `PASS` commands.
    *   **Telnet:** Entire session, including login, is unencrypted.
        *   *Filter:* `telnet`
        *   *Analysis:* Follow TCP stream.

3.  **Malware Communication:**
    *   **Command & Control (C&C) Beacons:** Infected machine regularly contacting a C&C server.
        *   *Analysis:* Look for repetitive connections to unusual external IP addresses or domains, often over non-standard ports or protocols (like DNS, ICMP, or plain TCP/UDP). Use `Statistics > Endpoints` or `Statistics > Conversations`. Filter by suspect IPs.
    *   **DNS Tunneling:** Using DNS queries/responses to exfiltrate data or for C&C.
        *   *Filter:* `dns`
        *   *Analysis:* Look for unusually long DNS queries, high volume of TXT record queries, queries to suspicious domains.
    *   **Suspicious Executable Downloads:** Downloads of `.exe`, `.dll`, `.ps1` files over HTTP.
        *   *Filter:* `http contains ".exe"` or `http contains ".dll"`
        *   *Analysis:* Follow stream, check `Content-Type` headers. Use `File > Export Objects > HTTP` to extract downloaded files (handle with extreme caution!).

4.  **ARP Spoofing (Man-in-the-Middle):** Attacker sends forged ARP messages to associate their MAC address with the IP address of another host (like the default gateway).
    *   *Filter:* `arp.duplicate-address-detected` or `arp.duplicate-address-frame`
    *   *Analysis:* Look for ARP replies where the same IP address is associated with different MAC addresses over time. Check `arp -a` on hosts.

5.  **Unusual Protocols or Ports:**
    *   Traffic using unexpected protocols (e.g., IRC, Telnet) or standard protocols on non-standard ports (e.g., HTTP on port 8080 is common, but SSH on port 80 might be suspicious).
    *   *Analysis:* Use `Statistics > Protocol Hierarchy` to see the distribution of protocols. Investigate unexpected entries.

6.  **Large Data Exfiltration:** Unexpectedly large amounts of data being sent *out* of the network.
    *   *Analysis:* Use `Statistics > Conversations` or `Statistics > Endpoints`, sort by 'Bytes' for outbound traffic (Source IP is internal, Destination IP is external). Investigate large flows to unknown destinations.

### Tips and Best Practices

*   **Start with a Goal:** Know what you're looking for before you start capturing.
*   **Use Capture Filters:** Capture only the traffic you need, especially for long-running captures or high-traffic networks.
*   **Master Display Filters:** This is key to efficient analysis. Learn the syntax and common filters.
*   **Coloring Rules:** Use `View > Coloring Rules` to highlight specific types of traffic automatically (e.g., red for RST packets, yellow for ARP, blue for DNS).
*   **Time Display Format:** Change time format (`View > Time Display Format`) for easier correlation (e.g., 'Seconds Since Beginning of Capture', 'UTC Date and Time of Day').
*   **Customize Columns:** Add/remove/reorder columns in the Packet List pane (`Edit > Preferences > Appearance > Columns`).
*   **`tshark`:** Use the command-line equivalent for scripting, automated captures, or remote analysis over SSH.
*   **Practice:** The best way to learn Wireshark is to use it regularly. Capture traffic while performing various network activities.

---
**Disclaimer:** Wireshark is a powerful tool. Use it responsibly and ethically. Capturing network traffic may require authorization, especially on networks you do not own or manage. Do not analyze traffic containing sensitive information without proper permissions and safeguards.
