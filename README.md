# Threat Intelligence Analysis & MITRE ATT&CK Mapping

**Author:** Farouq Hassan
**Focus Areas:** Threat Intelligence, MITRE ATT&CK, OSINT Analysis, Impact Scoring, Malware Analysis
**Subjects Covered:**

* APT29 (NOBELIUM) Campaign Analysis
* Lumma Stealer Malware Analysis

---

# Part 1 — APT29 (NOBELIUM) Campaign Analysis

📄 Source: 

---

## 1️⃣ Campaign Evolution

APT29 demonstrated a shift in initial access techniques:

### 2020 Campaign

* **Supply-chain compromise**
* Target: SolarWinds Orion
* Technique: T1195.002

### 2021 Campaign

* **Email spearphishing**
* Platform: USAID via Constant Contact
* Technique: T1566.002

This reflects strategic adaptation in initial access vectors.

(Page 1 )

---

## 2️⃣ Behavior Chain Summary

| Phase                | Observed Behavior                        |
| -------------------- | ---------------------------------------- |
| Initial Access       | Supply-chain compromise or spearphishing |
| Execution            | PowerShell-based execution               |
| Persistence          | Scheduled tasks, backdoors               |
| Privilege Escalation | Credential/token abuse                   |
| Defense Evasion      | Obfuscation                              |
| Discovery            | Account enumeration                      |
| Lateral Movement     | Remote services                          |
| Command & Control    | HTTP/S web-based                         |
| Collection           | Email + directory data                   |
| Exfiltration         | C2 channel                               |

(Page 1 )

---

## 3️⃣ ATT&CK Technique Impact Scoring

📄 Source: 

Impact scoring model:

* High = 90
* Medium = 60
* Low = 30

| Technique ID | Name                     | Impact      |
| ------------ | ------------------------ | ----------- |
| T1195.002    | Supply Chain Compromise  | High (90)   |
| T1566.002    | Spearphishing Link       | Medium (60) |
| T1204.002    | User Execution           | Medium (60) |
| T1059.001    | PowerShell               | Medium (60) |
| T1053.005    | Scheduled Task           | Medium (60) |
| T1550.001    | Access Token Abuse       | High (90)   |
| T1071.001    | Web C2                   | Medium (60) |
| T1027        | Obfuscation              | Medium (60) |
| T1087        | Account Discovery        | Low (30)    |
| T1041        | Exfiltration over C2     | Medium (60) |
| T1114        | Email Collection         | Medium (60) |
| T1003.001    | LSASS Credential Dumping | High (90)   |

(Page 2 )

---

## 4️⃣ Full ATT&CK Navigator JSON (Verbatim Appendix)

Below is the complete JSON used for ATT&CK Navigator:

```json
{
 "name": "NOBELIUM / APT29 – OSINT TTP mapping (impact-scored)",
 "version": "4.5",
 "domain": "enterprise-attack",
 "description": "OSINT-based ATT&CK technique mapping with impact-based scoring: High=90, Med=60, Low=30.",
 "filters": {
  "platforms": [
   "Windows",
   "Linux",
   "macOS",
   "Azure AD",
   "Office 365"
  ]
 },
 "sorting": 0,
 "layout": {
  "layout": "side",
  "showName": true,
  "showID": true
 },
 "techniques": [
  { "techniqueID": "T1195.002", "score": 90, "color": "#ff4d4d", "comment": "SolarWinds Orion supply-chain compromise." },
  { "techniqueID": "T1566.002", "score": 60, "color": "#ffb84d", "comment": "USAID/Constant Contact spearphishing links." },
  { "techniqueID": "T1204.002", "score": 60, "color": "#ffb84d", "comment": "User execution of malicious payload." },
  { "techniqueID": "T1059.001", "score": 60, "color": "#ffb84d", "comment": "PowerShell execution for staging." },
  { "techniqueID": "T1053.005", "score": 60, "color": "#ffb84d", "comment": "Scheduled Task persistence." },
  { "techniqueID": "T1550.001", "score": 90, "color": "#ff4d4d", "comment": "Access token and identity abuse." },
  { "techniqueID": "T1071.001", "score": 60, "color": "#ffb84d", "comment": "Web-based command and control." },
  { "techniqueID": "T1027", "score": 60, "color": "#ffb84d", "comment": "Payload obfuscation." },
  { "techniqueID": "T1087", "score": 30, "color": "#fff176", "comment": "Account discovery." },
  { "techniqueID": "T1041", "score": 60, "color": "#ffb84d", "comment": "Exfiltration over C2 channel." },
  { "techniqueID": "T1114", "score": 60, "color": "#ffb84d", "comment": "Email collection." },
  { "techniqueID": "T1003.001", "score": 90, "color": "#ff4d4d", "comment": "LSASS credential dumping." }
 ],
 "legendItems": [
  { "label": "High impact (90)", "color": "#ff4d4d" },
  { "label": "Medium impact (60)", "color": "#ffb84d" },
  { "label": "Low impact (30)", "color": "#fff176" }
 ]
}
```

(Full JSON shown on pages 3–4 )

---

# Part 2 — Lumma Stealer Malware Analysis

📄 Source: 

---

## 1️⃣ Malware Overview

Lumma Stealer is an information-stealing malware targeting:

* Credentials
* Browser data
* Cryptocurrency wallets

Common delivery methods:

* Phishing emails
* Malicious ads
* Cracked software installers

(Page 1 )

---

## 2️⃣ Delivery, Execution, Persistence

### Delivery

* Malicious email attachments or links

### Execution

* PowerShell
* Native Windows APIs

### Persistence

* Scheduled tasks
* Registry Run keys

(Page 1 )

---

## 3️⃣ Indicators of Compromise (IOCs)

| Type     | Indicator                                          |
| -------- | -------------------------------------------------- |
| File     | Randomized `.exe` in `%AppData%`                   |
| Network  | HTTP POST to hard-coded IP                         |
| Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run |

(Page 1 )

---

## 4️⃣ ATT&CK Mapping (JSON Extract)

📄 Source: 

```json
{
 "name": "Lumma Stealer ATT&CK Mapping",
 "version": "4.5",
 "domain": "enterprise-attack",
 "techniques": [
  { "techniqueID": "T1566.001", "score": 9, "comment": "Malspam delivery" },
  { "techniqueID": "T1204.002", "score": 8, "comment": "User execution" },
  { "techniqueID": "T1059.001", "score": 7, "comment": "PowerShell execution" },
  { "techniqueID": "T1053.005", "score": 8, "comment": "Scheduled task persistence" },
  { "techniqueID": "T1027", "score": 6, "comment": "Obfuscation" },
  { "techniqueID": "T1555", "score": 9, "comment": "Credential harvesting" },
  { "techniqueID": "T1005", "score": 7, "comment": "Local data collection" },
  { "techniqueID": "T1071.001", "score": 8, "comment": "HTTP C2" },
  { "techniqueID": "T1041", "score": 9, "comment": "Exfiltration over C2" }
 ]
}
```

---

## 5️⃣ Defensive Recommendations

From page 4 :

* Improve email filtering
* Restrict PowerShell execution
* Monitor outbound traffic
* Implement application whitelisting

---

# Comparative Analysis — APT29 vs Lumma

| Category         | APT29                        | Lumma Stealer                |
| ---------------- | ---------------------------- | ---------------------------- |
| Actor Type       | Nation-state                 | Cybercrime malware           |
| Initial Access   | Supply-chain / Spearphishing | Malspam / Phishing           |
| Credential Abuse | Access token abuse           | Browser/password store theft |
| C2               | Web-based HTTP/S             | HTTP POST hard-coded         |
| Impact           | Strategic espionage          | Credential/data theft        |

---

# Skills Demonstrated

* OSINT threat intelligence analysis
* MITRE ATT&CK mapping
* Impact scoring methodology
* ATT&CK Navigator JSON construction
* Malware behavioral analysis
* IOC identification
* Defensive control recommendations
* Cross-campaign comparison

---

# Security Value

This session demonstrates:

* Structured threat actor analysis
* Behavioral chain modeling
* Mapping real-world campaigns to ATT&CK
* Turning intelligence into defensive recommendations
* Bridging threat intel and blue-team strategy
