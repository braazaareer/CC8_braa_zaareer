# Apex.corp Security Assessment & Capstone Project

**Author:** Braa Zaareer
**Supervisor:** Eng. Mohanad Yousef
**Project Type:** Purple Team (Offensive & Defensive Engagement)

---

## 📋 Executive Summary

This project represents a comprehensive security assessment of the "Apex.corp" network environment. The engagement involved a full cyber-attack kill chain (Red Team) resulting in total network compromise, followed by a detailed forensic analysis and remediation plan (Blue Team).

The root cause of the compromise was identified as a failure in patch management (specifically Microsoft Outlook), insecure credential storage, and the use of End-of-Life (EOL) systems.

---

## 🏗️ Target Environment & Architecture

The network was logically segmented into a DMZ and an Internal LAN, simulating a small corporate environment.

| Hostname | OS | IP Address | Role | Key Services |
| --- | --- | --- | --- | --- |
| **Webserver** | Ubuntu Linux | 10.193.111.100 (Public) / 10.0.0.14 (LAN) | Public Web Server | Apache2 (RiteCMS), Node.js, SSH |
| **OMI Server** | Ubuntu Linux | 10.0.0.11 | Management Server | OMI Agent (`omid`), SSH |
| **FTP Server** | Windows XP | 10.0.0.15 | Legacy File Server | PCMan FTP Server, RDP |
| **tech-PC** | Windows 10 | 10.0.0.8 | IT Workstation | Outlook, RDP Client, SSH Client |

---

## ⚔️ Red Team Engagement (Offensive)

The offensive phase followed a standard kill chain methodology: **Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, and Lateral Movement**.

### 1. Reconnaissance (OSINT)

* **Discovery:** Identified employee "Sarah Chen - IT Systems Admin" via a public LinkedIn post.
* **Intel:** Screen analysis revealed the usage of Windows 10 and a vulnerable version of Microsoft Outlook.
* **Email Discovery:** Identified the target email `tech_IT@apex.corp`.

### 2. Initial Access & Credential Dumping

* **Vector:** Spear-phishing email disguised as a global security bulletin.
* **Vulnerability:** **CVE-2024-21413 (MonikerLink)** in Microsoft Outlook.
* **Exploit:** The email contained a malicious link (`file:\\10.0.0.5\MyShare\`) which bypassed "Protected View" and forced an SMB connection to the attacker's server, capturing the user's NTLMv2 hash.
* **Cracking:** The hash was cracked offline using `john`, revealing the IT Administrator's plaintext password.

### 3. Lateral Movement & Enumeration

* **Access:** RDP access gained to `tech-PC` (10.0.0.8) using cracked credentials.
* **Discovery:** Found a network map (`server_reference.txt`) and administrative credentials for the Webserver saved in the browser's password manager.

### 4. Web Server Compromise (RiteCMS)

* **Access:** Logged into RiteCMS admin panel using stolen credentials.
* **Vulnerability 1:** **Stored XSS (CVE-2024-28623)** in the "Menus" section used to steal session cookies.
* **Vulnerability 2:** **Unrestricted File Upload** in "Files Manager" allowed the upload of a PHP reverse shell (`test.php`), granting a shell as `www-data`.

### 5. Privilege Escalation (Node.js)

* **Discovery:** Internal Node.js service running on port 8080 using `tar-fs` v3.0.0.
* **Vulnerability:** **CVE-2024-12905** (Arbitrary File Write via Symlink).
* **Exploit:**
1. Uploaded a malicious tar archive creating a symlink to `/home/web/.bashrc`.
2. Uploaded a second archive writing through the symlink to inject a malicious echo command into `.bashrc`.
3. Waited for a legitimate user login to trigger the payload, adding the attacker's SSH key to `authorized_keys`.



### 6. Infrastructure Takeover

* **OMI Server (OMIGOD):** Pivoted to 10.0.0.11 and exploited **CVE-2021-38647** (OMI RCE). By removing the Authorization header in a web request, root access was achieved.
* **Legacy FTP Server:** Pivoted to 10.0.0.15 running PCMan FTP Server 2.0. Exploited **CVE-2025-4255** (Stack-based Buffer Overflow) using a custom Perl script to gain Administrator access.

---

## 🛡️ Blue Team Operations (Defensive)

Following the compromise, a full Incident Response (IR) and remediation process was conducted.

### 1. Root Cause Analysis

* **Human Factor:** OSINT leakage via social media and poor password hygiene (saving admin passwords in browsers).
* **Patch Management:** Critical failure to patch Outlook, Node.js packages, and OMI agents.
* **Legacy Systems:** Continued use of Windows XP and abandoned software (RiteCMS, PCMan FTP).

### 2. Forensics & IoC Discovery

* **Network Logs:** Identified outbound SMB traffic (Port 445) from `tech-PC` to the attacker's IP (Event ID 30807).
* **Authentication Logs:** Detected RDP login from external IP (Event ID 4624) and unauthorized SSH key additions in `/var/log/auth.log`.
* **File Artifacts:** Recovered the modified `.bashrc` containing the injection payload and the malicious `test.php` shell in the web directory.

### 3. MITRE ATT&CK Mapping

The attack was mapped to the MITRE framework, including:

* **T1593.001:** Search Open Websites/Domains (LinkedIn).
* **T1566:** Phishing (Outlook Exploit).
* **T1003.005:** OS Credential Dumping (NTLM Hashes).
* **T1068:** Exploitation for Privilege Escalation (tar-fs).
* **T1210:** Exploitation of Remote Services (OMIGOD).

### 4. Remediation & Hardening

* **Immediate Patches:** Updated OMI agent to v1.9.1.0 and `tar-fs` to v3.1.1.
* **Configuration:** Applied Group Policy Object (GPO) to disable "Offer to save passwords" in browsers and enforced strong password complexity.
* **Web Hardening:** Implemented Content Security Policy (CSP) headers in Apache to mitigate XSS.
* **Network Security:** Implemented UFW rules to restrict access to management ports (5986).
* **Migration:** Decommissioned Windows XP and RiteCMS in favor of supported alternatives (FileZilla Server on modern OS).

---

## 🛠️ Tools & Technologies Used

* **Recon & Scanning:** Nmap, FFUF.
* **Exploitation:** Metasploit (msfconsole, msfvenom), Python, Perl, Impacket-smbserver.
* **Cracking:** John the Ripper.
* **Connectivity:** SSH, RDP (xfreerdp), FTP.
* **Defensive:** Windows Event Viewer, UFW logs, Apache logs, Local Security Policy (secpol.msc).

---

## 📄 Disclaimer

This project was conducted in a controlled, simulated environment (CyberCamp8 Capstone) for educational and authorized testing purposes only. The exploits and techniques detailed here are for demonstrating security vulnerabilities and remediation strategies.

---

*Based on the CyberCamp8 Capstone Project Report by Braa Zaareer.*

Would you like me to organize this into a slide deck outline for a presentation?
