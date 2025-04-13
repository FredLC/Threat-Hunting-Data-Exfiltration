# Insider Threat Investigation: Suspicious Archiving Activity by Employee

## Scenario Overview

On April 12, 2025, the security team was alerted by management to investigate a potential insider threat involving an employee named **John Doe**, working in a sensitive department. John was recently placed on a **Performance Improvement Plan (PIP)**, and following a volatile outburst, concerns were raised about potential data exfiltration.

As a SOC analyst, I was tasked with investigating John's corporate workstation (`windows-target-1`) using **Microsoft Defender for Endpoint (MDE)** to ensure no malicious or suspicious activity was occurring.

---

## Hypothesis

Given John's administrative access to his workstation and unrestricted software usage, it was hypothesized that he might attempt to:
- **Archive or compress sensitive files**
- **Transfer the archived data to an external or cloud storage location**

---

## Investigation Summary

### 1. Detection of Archiving Activity with 7-Zip

Using a KQL query, I searched for known archiving applications being executed. Notably, `7z.exe` was used on `.csv` files, which often contain structured data, potentially including proprietary or sensitive information.

```kql
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "windows-target-1";
DeviceProcessEvents
| where DeviceName == VMName
| where FileName has_any(archive_applications)
| order by Timestamp desc
```

![query1](https://github.com/user-attachments/assets/e4e4ff82-5b4b-4e2c-9089-2a5716098d46)


---

### 2. File Movements to a Suspicious Directory

I examined file system events around the time `7z.exe` was used. This revealed that files were moved to a directory named `backup`, which could have been prepared for exfiltration.

```kql
let specificTime = datetime(2025-04-12T04:49:48.5615171Z);
let VMName = "windows-target-1";
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
```

![query2](https://github.com/user-attachments/assets/e7844f3d-f73e-4041-b436-31ff2913e569)


---

### 3. Network Traffic Review – No Signs of Exfiltration

To determine whether any data was exfiltrated, I analyzed outbound network connections 10 minutes before and after the archiving activity. No connections to remote storage services or unusual external IPs were detected.

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-04-12T04:49:48.5615171Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
```

---

## Conclusion

While John did use **7-Zip** to archive several `.csv` files and moved them into a `backup` folder, **no evidence of network-based data exfiltration** was found during the investigation window. However, these actions still raise red flags and may warrant further monitoring or HR intervention.

---

## MITRE ATT&CK Mapping

| Technique | Description | ID |
|----------|-------------|----|
| **T1560.001** | Archive via Utility (7-Zip) | [T1560.001](https://attack.mitre.org/techniques/T1560/001) |
| **T1074.001** | Local Data Staging (e.g., `backup` folder) | [T1074.001](https://attack.mitre.org/techniques/T1074/001) |
| **T1041** | (Not observed) Exfiltration Over C2 Channel or Public Cloud | [T1041](https://attack.mitre.org/techniques/T1041/) |

---

## Mitigation Recommendations

- **Application Whitelisting**: Prevent execution of unauthorized archiving tools like `7z.exe` unless explicitly approved.
- **DLP Policies**: Apply Data Loss Prevention rules to detect and prevent compression or transfer of sensitive data.
- **Access Control Review**: Review and limit administrative privileges for users flagged for HR incidents.
- **User Behavior Analytics (UBA)**: Monitor for anomalous behavior such as large-scale file access or creation of backup folders.
- **Employee Awareness & Policy Enforcement**: Ensure employees are aware of security policies and legal implications of data theft.

---

## Remediation Steps

- Isolate or restrict the affected user's device pending further HR action.
- Conduct a full forensic review of John's user account and device.
- Review and classify contents of the archived `.csv` files for sensitivity.
- Implement alerting for archiving and data movement activities in sensitive departments.
