# Alert Title: Qilin Ransomware Encryption Activity Detected

<br>

## **Description**
The Qilin ransomware gang (also known as Agenda) is a prolific Russian-speaking ransomware-as-a-service operation that has escalated significantly in 2025, targeting critical infrastructure, manufacturing, and corporate environments. 
In one high-profile incident, Qilin claimed responsibility for a cyberattack on Japan’s Asahi Group Holdings, which paralyzed production systems at multiple facilities and disrupted logistics and order management processes, with alleged theft of internal documents and data. 
Qilin’s operators often employ credential abuse, living-off-the-land tools, and hybrid encryption tactics to evade detection and amplify impact, and have been linked to attacks on Covenant Health and other large organizations. 
Their double-extortion model not only encrypts victim data but also threatens public disclosure of stolen information to pressure payment. 

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
■ **T1486 – Data Encrypted for Impact**: https://attack.mitre.org/techniques/T1486/  <br>
■ **T1490 – Inhibit System Recovery**: https://attack.mitre.org/techniques/T1490/  <br>
■ **T1059 – Command and Scripting Interpreter**: https://attack.mitre.org/techniques/T1059/  <br>
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>
■ **T1562.001 – Impair Defenses**: https://attack.mitre.org/techniques/T1562/001/  <br>

<br>

## **Severity**
**High**: Encryption and recovery inhibition strongly indicates active ransomware execution.

<br>

## **Detection Type** 
■ Behavioural Detection  <br>
■ TTP‑based  <br>

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `DeviceProcessEvents`  `DeviceFileEvents` 

<br>

## **False Positives**
■ Legitimate backup cleanup scripts.  <br>
■ Admin-driven VSS maintenance.  <br>
■ Bulk file renaming tools.  <br>


<br>

--- 


## **KQL Query**

```kusto


// ----- Tunables -----
let lookback             = 3d;       // How far back to hunt
let correlation_window   = 30m;      // Time window between defense evasion and encryption surge
let min_encrypted_files  = 50;       // Threshold for "mass encryption"
let min_distinct_dirs    = 5;        // Threshold for breadth of impact

// --- Parameters / lists ---
let RansomExtensions = dynamic([".qilin", ".agenda", ".locked"]);
let RansomNotes      = dynamic(["README.txt", "HOW_TO_DECRYPT.txt", "README_AGENDA.txt"]);
let EvasionTerms     = dynamic([
    "delete shadows",
    "shadowcopy delete",
    "bcdedit /set",
    "recoveryenabled no",
    "wevtutil cl",
    "Clear-EventLog"
]);

// ---- Stage 1: Ransomware preparation & defense evasion ----
let DefenseEvasion =
    DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where FileName in~ ("vssadmin.exe","wmic.exe","bcdedit.exe","wevtutil.exe","powershell.exe","cmd.exe")
    | extend ActorUser = tolower(coalesce(
        column_ifexists("AccountName",""),
        column_ifexists("InitiatingProcessAccountName",""),
        column_ifexists("InitiatingProcessAccountUpn","")
    ))
    | where isnotempty(ActorUser)
    | where ProcessCommandLine has_any (EvasionTerms)
    | project
        DE_Time = TimeGenerated,
        DeviceName,
        ActorUser,
        DE_FileName = FileName,
        ProcessCommandLine;

// ---- Stage 2: Mass file encryption behavior ----
let EncryptionActivity =
    DeviceFileEvents
    | where TimeGenerated > ago(lookback)
    | extend ActorUser = tolower(coalesce(
        column_ifexists("AccountName",""),
        column_ifexists("InitiatingProcessAccountName",""),
        column_ifexists("InitiatingProcessAccountUpn","")
    ))
    | where isnotempty(ActorUser)
    | where ActionType in~ ("FileCreated", "FileRenamed")
    // Extract true file extension and compare to the list
    | extend FileExt = extract(@"\.[^.]+$", 0, FileName)
    | where FileExt in (RansomExtensions)
    | summarize
        EncryptedFileCount = count(),
        DistinctDirectories = dcount(FolderPath),
        EA_Start = min(TimeGenerated),
        EA_End   = max(TimeGenerated)
        by DeviceName, ActorUser, EA_Window = bin(TimeGenerated, 5m)
    | where EncryptedFileCount > min_encrypted_files and DistinctDirectories > min_distinct_dirs;

// ---- Stage 3: Ransom note creation ----
let RansomNoteActivity =
    DeviceFileEvents
    | where TimeGenerated > ago(lookback)
    | extend ActorUser = tolower(coalesce(
        column_ifexists("AccountName",""),
        column_ifexists("InitiatingProcessAccountName",""),
        column_ifexists("InitiatingProcessAccountUpn","")
    ))
    | where isnotempty(ActorUser)
    | where ActionType == "FileCreated"
    | where FileName in (RansomNotes)
    // Collapse to earliest note per device/user to avoid duplicates
    | summarize
        RN_Time     = min(TimeGenerated),
        RN_FileName = any(FileName),
        RN_Path     = any(FolderPath)
        by DeviceName, ActorUser;

// ---- Correlation ----
DefenseEvasion
| join kind=inner EncryptionActivity on DeviceName, ActorUser
| where EA_Start between (DE_Time .. DE_Time + correlation_window)
| join kind=leftouter RansomNoteActivity on DeviceName, ActorUser
| project
    DE_Time,
    DeviceName,
    ActorUser,
    DE_FileName,
    ProcessCommandLine,
    EncryptedFileCount,
    DistinctDirectories,
    EA_Start,
    EA_End,
    RN_Time,
    RN_FileName,
    RN_Path
| order by DE_Time desc




```

--- 
<br>

## **References**
■ Searle, P. (2025) Cybercriminals claim hack on Japan’s Asahi Group [Online]. Available at: https://www.reuters.com/world/asia-pacific/cybercriminals-claim-hack-japans-asahi-group-2025-10-07/

<br>

## **Author**
**Faiza Aslam**
