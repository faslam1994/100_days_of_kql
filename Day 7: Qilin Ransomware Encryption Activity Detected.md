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


let RansomExtensions = dynamic([".qilin", ".agenda", ".locked"]);
let RansomNotes = dynamic(["README.txt", "HOW_TO_DECRYPT.txt", "README_AGENDA.txt"]);
let SuspiciousLOLBins = dynamic([
    "vssadmin.exe",
    "wmic.exe",
    "bcdedit.exe",
    "wevtutil.exe",
    "powershell.exe",
    "cmd.exe"
]);

// ---- Stage 1: Ransomware preparation & defense evasion ----
let DefenseEvasion =
    DeviceProcessEvents
    | where FileName in (SuspiciousLOLBins)
    | where ProcessCommandLine has_any (
        "delete shadows",
        "shadowcopy delete",
        "bcdedit /set",
        "recoveryenabled no",
        "wevtutil cl",
        "Clear-EventLog"
    )
    | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine;

// ---- Stage 2: Mass file encryption behavior ----
let EncryptionActivity =
    DeviceFileEvents
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FileName has_any (RansomExtensions)
    | summarize
        EncryptedFileCount = count(),
        DistinctDirectories = dcount(FolderPath)
        by DeviceName, AccountName, bin(TimeGenerated, 5m)
    | where EncryptedFileCount > 50 and DistinctDirectories > 5;

// ---- Stage 3: Ransom note creation ----
let RansomNoteActivity =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FileName in (RansomNotes)
    | project TimeGenerated, DeviceName, AccountName, FolderPath, FileName;

// ---- Correlation ----
DefenseEvasion
| join kind=inner EncryptionActivity on DeviceName, AccountName
| join kind=leftouter RansomNoteActivity on DeviceName, AccountName
| where EncryptionActivity.TimeGenerated between (DefenseEvasion.TimeGenerated .. DefenseEvasion.TimeGenerated + 30m)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    EncryptedFileCount,
    DistinctDirectories,
    RansomNote = FileName1,
    RansomNotePath = FolderPath
| order by TimeGenerated desc



```

--- 
<br>

## **References**
■ Searle, P. (2025) Cybercriminals claim hack on Japan’s Asahi Group [Online]. Available at: https://www.reuters.com/world/asia-pacific/cybercriminals-claim-hack-japans-asahi-group-2025-10-07/

<br>

## **Author**
**Faiza Aslam**
