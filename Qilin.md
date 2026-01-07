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
