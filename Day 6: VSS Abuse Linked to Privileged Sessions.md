# Alert Title: VSS Abuse Linked to Privileged Sessions

<br>

## **Description**
This rule detects potential credential‑theft or shadow‑copy tampering by correlating VSS‑related process executions (such as vssadmin shadow commands) with privileged logons, successful logon sessions, and access to highly sensitive files like ntds.dit, SAM, and SYSTEM. 
It extracts and normalizes the LogonId from both native event fields and embedded XML to reliably join events across process, logon, and file‑access telemetry. 
The final output highlights suspicious activity performed under the same LogonId, enabling analysts to trace attacker lateral movement or SYSTEM‑level misuse with high fidelity.
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/96ffcafe-f8b4-410d-9544-7a4feae3e044" />

<br>

## **Threats**
■ **APT28 (aka Fancy Bear)**  <br>
■ **APT41** <br>
■ **HAFNIUM** <br>

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Credential Access <br>
■ Execution <br>
■ Exfiltration <br>
■ Defense Evasion <br>
■ Command and Control <br>
  

<br>

### **Techniques**
■ **T1003.003 – OS Credential Dumping: NTDS**: https://attack.mitre.org/techniques/T1003/003/ <br>
■ **T1003 – OS Credential Dumping**: https://attack.mitre.org/techniques/T1003/ <br>
■ **T1059 – Command and Scripting Interpreter**: https://attack.mitre.org/techniques/T1059/ <br>
■ **T1105 – Ingress Tool Transfer**: https://attack.mitre.org/techniques/T1105/ <br>
■ **T1070.004 – Indicator Removal: File Deletion (Shadow Copy Deletion)**: https://attack.mitre.org/techniques/T1070/004/ <br>
■ **T1560 – Archive Collected Data**: https://attack.mitre.org/techniques/T1560/ <br>
■ **T1041 – Exfiltration Over C2 Channel**: https://attack.mitre.org/techniques/T1041/ <br>
■ **T1567.002 – Exfiltration to Cloud Storage**: https://attack.mitre.org/techniques/T1567/002/ <br>

<br>

## **Severity**
**High**: As the detection uncovers attempts to access or copy domain‑wide credential stores (NTDS/SAM/SYSTEM), which can lead to full Active Directory compromise.

<br>

## **Detection Type** 
■ Behavioural Detection  <br>
■ TTP‑based  <br>

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Windows - Endpoint**: `SecurityEvent`  

<br>

## **False Positives**
■ Legitimate system backups, maintenance tasks, or security tools that create or read shadow copies (e.g., backup agents, EDR scanners, or domain controller health checks) may generate similar activity. <br>

<br>

--- 


## **KQL Query**

```kusto


// ==============================
// Correlate VSS Shadow-Copy Usage with Privileged Logons and Sensitive File Access
// Goal: Detect sessions where vssadmin/wmic/powershell/cmd perform shadow-copy operations,
//       then correlate the same LogonId to privileged logons and access to NTDS/SAM/SYSTEM.
// ==============================

// ---- Define processes commonly used for VSS/shadow operations ----
let VssProcesses = dynamic(["vssadmin.exe", "wmic.exe", "powershell.exe", "cmd.exe"]);

// ---- Define highly sensitive targets frequently copied from shadow volumes ----
let SensitiveFiles = dynamic([
    @"C:\Windows\NTDS\ntds.dit",
    @"C:\Windows\System32\config\SAM",
    @"C:\Windows\System32\config\SYSTEM"
]);

// ---- Process execution: look for shadow-related commands from VSS-capable binaries ----
// Note: We extract SubjectLogonId from EventData XML as a fallback to ensure reliable joins.
let VSS_ProcessExecution =
    SecurityEvent
    | where EventID == 4688
    | where NewProcessName has_any (VssProcesses)
    | where CommandLine has "shadow"                      // e.g., "vssadmin create/list/delete shadow"
    | extend LogonIdFromXml = tostring(extract(@"Name=""SubjectLogonId""&gt;([^&lt;]+)&lt;", 1, EventData))
    | project
        TimeGenerated,
        Computer,
        Account       = SubjectUserName,
        AccountDomain = SubjectDomainName,
        LogonId       = coalesce(SubjectLogonId, LogonIdFromXml),
        NewProcessName,
        CommandLine;

// ---- Privileged logons: EventID 4672 indicates special privileges (e.g., SeDebugPrivilege) ----
let PrivilegedLogons =
    SecurityEvent
    | where EventID == 4672
    | extend LogonIdFromXml = tostring(extract(@"Name=""SubjectLogonId""&gt;([^&lt;]+)&lt;", 1, EventData))
    | project
        PrivLogonTime = TimeGenerated,
        Computer,
        PrivAccount    = SubjectUserName,
        PrivDomain     = SubjectDomainName,
        LogonId        = coalesce(SubjectLogonId, LogonIdFromXml);

// ---- Successful logons for context and source IP: EventID 4624 ----
let SuccessfulLogons =
    SecurityEvent
    | where EventID == 4624
    | extend LogonIdFromXml = tostring(extract(@"Name=""SubjectLogonId""&gt;([^&lt;]+)&lt;", 1, EventData))
    | project
        LogonTime     = TimeGenerated,
        Computer,
        Account       = SubjectUserName,
        AccountDomain = SubjectDomainName,
        LogonType,
        LogonId       = coalesce(SubjectLogonId, LogonIdFromXml),
        IpAddress;

// ---- Sensitive file access: EventID 4663 (Object Access) hitting NTDS/SAM/SYSTEM paths ----
// Note: Requires Object Access auditing on these paths; we also normalize LogonId via XML fallback.
let NTDS_FileAccess =
    SecurityEvent
    | where EventID == 4663
    | where ObjectName has_any (SensitiveFiles)
    | extend LogonIdFromXml = tostring(extract(@"Name=""SubjectLogonId""&gt;([^&lt;]+)&lt;", 1, EventData))
    | project
        FileAccessTime = TimeGenerated,
        Computer,
        FileName       = ObjectName,
        AccessMask,
        Account        = SubjectUserName,
        LogonId        = coalesce(SubjectLogonId, LogonIdFromXml);

// ---- Correlate: Join on Computer + LogonId to stitch process, privilege, logon, and file access ----
// Result highlights events where the same session (LogonId) performed shadow ops and touched sensitive files.
VSS_ProcessExecution
| join kind=leftouter PrivilegedLogons   on Computer, LogonId
| join kind=leftouter SuccessfulLogons   on Computer, LogonId
| join kind=leftouter NTDS_FileAccess    on Computer, LogonId
| project
    TimeGenerated,
    Computer,
    Account,
    AccountDomain,
    PrivAccount,
    NewProcessName,
    CommandLine,
    IpAddress,
    FileName,
    AccessMask,
    LogonId                                     // <-- explicit separate column
| order by TimeGenerated desc


```

--- 
<br>

## **References**
■ Red Canary (2025) It’s All Fun and Games Until Ransomware Deletes the Shadow Copies, Red Canary [Blog]. Available at: https://redcanary.com/blog/threat-detection/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies/

<br>

## **Author**
**Faiza Aslam**
