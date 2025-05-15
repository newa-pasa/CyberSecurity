# Cybersecurity Automation & Scripting
 
-- Using Python for security automation
-- Hands-on: Writing basic security scripts

**Cybersecurity Automation** involves using technology and scripts to perform security tasks and processes with minimal human intervention. The goal is to improve efficiency, consistency, speed, and accuracy in handling security operations.

**Scripting** is the act of writing small programs (scripts) to automate tasks. In cybersecurity, common scripting languages include Python, Bash, PowerShell.

## Using Python for security automation

Python is a highly popular language for cybersecurity automation due to its:
*   **Simplicity and Readability:** Easy to learn and write.
*   **Extensive Libraries:** A vast collection of third-party libraries relevant to security tasks (networking, web requests, data analysis, cryptography, etc.).
*   **Cross-Platform Compatibility:** Scripts can often run on Windows, Linux, and macOS with minimal changes.
*   **Strong Community Support:** Large community and abundant resources.
*   **Integration Capabilities:** Easily integrates with other tools and APIs.

**Common Cybersecurity Tasks Automated with Python:**

1.  **Log Analysis & Parsing:**
    *   Reading log files (e.g., web server logs, system logs).
    *   Parsing log entries using regular expressions or string manipulation.
    *   Extracting relevant information (IP addresses, timestamps, error codes).
    *   Identifying patterns or anomalies.

2.  **Network Scanning & Reconnaissance:**
    *   Port scanning (e.g., using `socket` library or wrapping Nmap).
    *   Banner grabbing.
    *   Automating OSINT tasks (e.g., querying APIs of services like Shodan, VirusTotal).

3.  **Vulnerability Assessment:**
    *   Automating checks for common vulnerabilities.
    *   Interacting with vulnerability scanner APIs.
    *   Parsing vulnerability scan reports.

4.  **Malware Analysis (Basic):**
    *   Extracting strings from binaries.
    *   Calculating file hashes.
    *   Interacting with sandbox APIs.

5.  **Incident Response:**
    *   Automating data collection during an incident (e.g., fetching logs, system information).
    *   Automating containment actions (e.g., blocking an IP address on a firewall via API).
    *   Generating incident reports.

6.  **Web Application Security Testing:**
    *   Sending HTTP requests (using `requests` library).
    *   Scraping websites for information.
    *   Testing for common vulnerabilities like XSS or SQL injection (with caution and permission).

7.  **Data Encryption & Hashing:**
    *   Implementing cryptographic functions using libraries like `cryptography` or `hashlib`.

8.  **Automating Repetitive Tasks:**
    *   Backups, report generation, user provisioning checks.

**Key Python Libraries for Cybersecurity:**
*   **`requests`:** For making HTTP requests (interacting with web services and APIs).
*   **`socket`:** Low-level networking interface.
*   **`Scapy`:** Powerful packet manipulation library.
*   **`Nmap` (`python-nmap`):** Python wrapper for the Nmap scanner.
*   **`BeautifulSoup` / `lxml`:** For parsing HTML and XML (web scraping).
*   **`re` (Regular Expressions):** For pattern matching in text and logs.
*   **`os` / `subprocess`:** For interacting with the operating system and running external commands.
*   **`paramiko`:** For SSHv2 protocol implementation (automating SSH tasks).
*   **`cryptography`:** For cryptographic operations.
*   **`hashlib`:** For hashing algorithms.
*   **`pandas` / `numpy`:** For data analysis and manipulation (useful for large log datasets).
*   **`json` / `csv`:** For working with JSON and CSV data formats.

## Hands-on: Writing basic security scripts

This section involves writing and executing Python scripts to perform simple security-related tasks.

**Conceptual Hands-on Script Examples:**

1.  **Port Scanner:**
    *   **Goal:** Write a Python script to check if specific ports are open on a target IP address.
    *   **Libraries:** `socket`
    *   **Steps:**
        *   Get target IP and a list of ports from the user or define them in the script.
        *   Loop through each port.
        *   Try to establish a TCP connection to the target IP and port using `socket.connect_ex()`.
        *   If the connection is successful (returns 0), the port is open.
        *   Print the status of each port.
    *   **Example Snippet:**
      ```python
      import socket
      target_ip = "127.0.0.1" # Example: scan localhost
      ports_to_scan = [21, 22, 80, 443, 8080]
      for port in ports_to_scan:
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.settimeout(1) # Timeout for connection attempt
          result = sock.connect_ex((target_ip, port))
          if result == 0:
              print(f"Port {port}: Open")
          else:
              print(f"Port {port}: Closed")
          sock.close()
      ```

2.  **File Hasher:**
    *   **Goal:** Create a script that calculates the MD5 or SHA-256 hash of a given file.
    *   **Libraries:** `hashlib`
    *   **Steps:**
        *   Get the file path from the user.
        *   Open the file in binary read mode (`'rb'`).
        *   Read the file in chunks to handle large files efficiently.
        *   Update the hash object with each chunk.
        *   Print the hexadecimal representation of the hash.
    *   **Example Snippet (SHA256):**
      ```python
      import hashlib
      filename = "my_document.txt" # Replace with actual file
      sha256_hash = hashlib.sha256()
      try:
          with open(filename, "rb") as f:
              for byte_block in iter(lambda: f.read(4096), b""): # Read in 4KB chunks
                  sha256_hash.update(byte_block)
          print(f"SHA256 hash of {filename}: {sha256_hash.hexdigest()}")
      except FileNotFoundError:
          print(f"Error: File '{filename}' not found.")
      ```

3.  **Basic Web Server Log Analyzer:**
    *   **Goal:** Read a web server access log (e.g., Apache common log format) and count occurrences of 404 errors or list unique IP addresses.
    *   **Libraries:** `re` (optional, for more complex parsing)
    *   **Steps:**
        *   Open the log file.
        *   Read line by line.
        *   Split each line or use regex to extract relevant fields (IP address, status code).
        *   Count 404s or add IPs to a set to get unique IPs.
        *   Print the results.
    *   **Example Snippet (Count 404s):**
      ```python
      log_file = "access.log" # Replace with actual log file
      count_404 = 0
      try:
          with open(log_file, "r") as f:
              for line in f:
                  parts = line.split()
                  # Assuming status code is typically the 9th element (0-indexed) in common log format
                  # This is a simplification; regex is more robust
                  if len(parts) > 8 and parts[8] == "404":
                      count_404 = 1
          print(f"Number of 404 errors: {count_404}")
      except FileNotFoundError:
          print(f"Error: File '{log_file}' not found.")
      ```

4.  **Automating a Simple OSINT Task (e.g., DNS Lookup):**
    *   **Goal:** Get A records for a given domain.
    *   **Libraries:** `socket`
    *   **Example Snippet:**
      ```python
      import socket
      domain_name = "google.com"
      try:
          ip_address = socket.gethostbyname(domain_name)
          print(f"IP Address for {domain_name}: {ip_address}")
          # For multiple A records, socket.getaddrinfo is more comprehensive
          # all_info = socket.getaddrinfo(domain_name, None, socket.AF_INET, socket.SOCK_STREAM)
          # for item in all_info:
          #    print(f"IP: {item[4][0]}")
      except socket.gaierror:
          print(f"Error: Could not resolve hostname {domain_name}")
      ```

**Important Considerations for Scripting:**
*   **Error Handling:** Implement `try-except` blocks to gracefully handle errors (e.g., file not found, network issues).
*   **Input Validation:** Validate user inputs to prevent errors or potential security issues.
*   **Permissions:** Be mindful of the permissions required to run scripts, especially those interacting with system resources or network sockets.
*   **Ethical Use:** Always use scripting skills responsibly and ethically. Do not write or use scripts for unauthorized activities.
*   **Modularity:** Break down complex tasks into smaller functions for better organization and reusability.
*   **Comments:** Add comments to explain your code.
