# Apex.corp Security Assessment & Capstone Project

**Author:** Braa Zaareer  
**Supervisor:** Eng. Mohanad Yousef  
**Project Type:** Purple Team (Offensive & Defensive Engagement)

---

## 📋 Executive Summary
This project represents a comprehensive security assessment of the "Apex.corp" network environment. [cite_start]The engagement involved a full cyber-attack kill chain (Red Team) resulting in total network compromise, followed by a detailed forensic analysis and remediation plan (Blue Team)[cite: 27, 28, 29].

[cite_start]The root cause of the compromise was identified as a failure in patch management (specifically Microsoft Outlook), insecure credential storage, and the use of End-of-Life (EOL) systems[cite: 33, 37].

---

## 🏗️ Target Environment & Architecture
[cite_start]The network was logically segmented into a DMZ and an Internal LAN, simulating a small corporate environment[cite: 57].

| Hostname | OS | IP Address | Role | Key Services |
| :--- | :--- | :--- | :--- | :--- |
| **Webserver** | Ubuntu Linux | 10.193.111.100 (Public) / 10.0.0.14 (LAN) | Public Web Server | [cite_start]Apache2 (RiteCMS), Node.js, SSH [cite: 63] |
| **OMI Server** | Ubuntu Linux | 10.0.0.11 | Management Server | [cite_start]OMI Agent (`omid`), SSH [cite: 67] |
| **FTP Server** | Windows XP | 10.0.0.15 | Legacy File Server | [cite_start]PCMan FTP Server, RDP [cite: 70] |
| **tech-PC** | Windows 10 | 10.0.0.8 | IT Workstation | [cite_start]Outlook, RDP Client, SSH Client [cite: 73] |

---

## ⚔️ Red Team Engagement (Offensive)

[cite_start]The offensive phase followed a standard kill chain methodology: **Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, and Lateral Movement**[cite: 80].

### 1. Reconnaissance (OSINT)
* [cite_start]**Discovery:** Identified employee "Sarah Chen - IT Systems Admin" via a public LinkedIn post[cite: 83].
* [cite_start]**Intel:** Screen analysis revealed the usage of Windows 10 and a vulnerable version of Microsoft Outlook[cite: 85].
* [cite_start]**Email Discovery:** Identified the target email `tech_IT@apex.corp`[cite: 93].

### 2. Initial Access & Credential Dumping
* [cite_start]**Vector:** Spear-phishing email disguised as a global security bulletin[cite: 116].
* **Vulnerability:** **CVE-2024-21413 (MonikerLink)** in Microsoft Outlook.
* [cite_start]**Exploit:** The email contained a malicious link (`file:\\10.0.0.5\MyShare\`) which bypassed "Protected View" and forced an SMB connection to the attacker's server, capturing the user's NTLMv2 hash[cite: 128].
* [cite_start]**Cracking:** The hash was cracked offline using `john`, revealing the IT Administrator's plaintext password[cite: 160].

### 3. Lateral Movement & Enumeration
* [cite_start]**Access:** RDP access gained to `tech-PC` (10.0.0.8) using cracked credentials[cite: 166].
* [cite_start]**Discovery:** Found a network map (`server_reference.txt`) and administrative credentials for the Webserver saved in the browser's password manager[cite: 182, 186].

### 4. Web Server Compromise (RiteCMS)
* **Access:** Logged into RiteCMS admin panel using stolen credentials.
* [cite_start]**Vulnerability 1:** **Stored XSS (CVE-2024-28623)** in the "Menus" section used to steal session cookies[cite: 217].
* [cite_start]**Vulnerability 2:** **Unrestricted File Upload** in "Files Manager" allowed the upload of a PHP reverse shell (`test.php`), granting a shell as `www-data`[cite: 316, 337].

### 5. Privilege Escalation (Node.js)
* [cite_start]**Discovery:** Internal Node.js service running on port 8080 using `tar-fs` v3.0.0[cite: 368, 425].
* **Vulnerability:** **CVE-2024-12905** (Arbitrary File Write via Symlink).
* **Exploit:**
    1.  Uploaded a malicious tar archive creating a symlink to `/home/web/.bashrc`.
    2.  Uploaded a second archive writing through the symlink to inject a malicious echo command into `.bashrc`.
    3.  [cite_start]Waited for a legitimate user login to trigger the payload, adding the attacker's SSH key to `authorized_keys`[cite: 438, 447].

### 6. Infrastructure Takeover
* **OMI Server (OMIGOD):** Pivoted to 10.0.0.11 and exploited **CVE-2021-38647** (OMI RCE). [cite_start]By removing the Authorization header in a web request, root access was achieved[cite: 483, 494].
* **Legacy FTP Server:** Pivoted to 10.0.0.15 running PCMan FTP Server 2.0. [cite_start]Exploited **CVE-2025-4255** (Stack-based Buffer Overflow) using a custom Perl script to gain Administrator access[cite: 535, 544].

---

## 🛡️ Blue Team Operations (Defensive)

Following the compromise, a full Incident Response (IR) and remediation process was conducted.

### 1. Root Cause Analysis
* [cite_start]**Human Factor:** OSINT leakage via social media and poor password hygiene (saving admin passwords in browsers)[cite: 585, 589].
* [cite_start]**Patch Management:** Critical failure to patch Outlook, Node.js packages, and OMI agents[cite: 38, 591].
* [cite_start]**Legacy Systems:** Continued use of Windows XP and abandoned software (RiteCMS, PCMan FTP)[cite: 593].

### 2. Forensics & IoC Discovery
* [cite_start]**Network Logs:** Identified outbound SMB traffic (Port 445) from `tech-PC` to the attacker's IP (Event ID 30807)[cite: 760].
* [cite_start]**Authentication Logs:** Detected RDP login from external IP (Event ID 4624) and unauthorized SSH key additions in `/var/log/auth.log`[cite: 790, 864].
* [cite_start]**File Artifacts:** Recovered the modified `.bashrc` containing the injection payload and the malicious `test.php` shell in the web directory[cite: 848, 842].

### 3. MITRE ATT&CK Mapping
The attack was mapped to the MITRE framework, including:
* [cite_start]**T1593.001:** Search Open Websites/Domains (LinkedIn)[cite: 916].
* [cite_start]**T1566:** Phishing (Outlook Exploit)[cite: 917].
* [cite_start]**T1003.005:** OS Credential Dumping (NTLM Hashes)[cite: 917].
* [cite_start]**T1068:** Exploitation for Privilege Escalation (tar-fs)[cite: 918].
* [cite_start]**T1210:** Exploitation of Remote Services (OMIGOD)[cite: 919].

### 4. Remediation & Hardening
* [cite_start]**Immediate Patches:** Updated OMI agent to v1.9.1.0 and `tar-fs` to v3.1.1[cite: 1338, 1242].
* [cite_start]**Configuration:** Applied Group Policy Object (GPO) to disable "Offer to save passwords" in browsers and enforced strong password complexity[cite: 1049, 1149].
* [cite_start]**Web Hardening:** Implemented Content Security Policy (CSP) headers in Apache to mitigate XSS[cite: 1178].
* [cite_start]**Network Security:** Implemented UFW rules to restrict access to management ports (5986)[cite: 1339].
* [cite_start]**Migration:** Decommissioned Windows XP and RiteCMS in favor of supported alternatives (FileZilla Server on modern OS)[cite: 1396].

---

## 🛠️ Tools & Technologies Used
* [cite_start]**Recon & Scanning:** Nmap, FFUF[cite: 1475, 1478].
* [cite_start]**Exploitation:** Metasploit (msfconsole, msfvenom), Python, Perl, Impacket-smbserver[cite: 1476, 1481].
* [cite_start]**Cracking:** John the Ripper[cite: 1477].
* [cite_start]**Connectivity:** SSH, RDP (xfreerdp), FTP[cite: 1483, 1485].
* **Defensive:** Windows Event Viewer, UFW logs, Apache logs, Local Security Policy (secpol.msc).

---

## 📄 Disclaimer
This project was conducted in a controlled, simulated environment (CyberCamp8 Capstone) for educational and authorized testing purposes only. The exploits and techniques detailed here are for demonstrating security vulnerabilities and remediation strategies.

---
*Based on the CyberCamp8 Capstone Project Report by Braa Zaareer.*
