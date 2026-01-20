# Alert Title: Suspicious Excel Macro Execution via Phishing Attachment
<br>

## **Description**
This detection identifies **macro-based malware activity** delivered through phishing emails containing Excel attachments (e.g., `.xls`, `.xlsm`). <br>
Instead of relying on static file hashes, this query uses **behavior-based detection** to identify when a user opens an Excel attachment from Outlook and the document executes macros that spawn suspicious child processes. <br>
<br>
**This helps analysts quickly**: <br>
■ Detect macro malware variants that evade hash-based signatures <br>
■ Identify phishing-driven initial access attempts <br>
■ Correlate email delivery with endpoint execution behavior <br>

<br>
<br>

## **Threats**
■ Excel macro viruses (e.g., MSExcel.Laroux-like behavior) <br>
■ Credential theft or malware staging via macro execution <br>
■ Post-phishing execution and persistence mechanisms <br>

<br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Execution <br>

<br>

### **Techniques**
■ **T1566.001 – Phishing: Spearphishing Attachment:** https://attack.mitre.org/techniques/T1566/001/ <br>
■ **T1204.002 – User Execution: Malicious File:** https://attack.mitre.org/techniques/T1204/002/ <br>
■ **T1059 – Command and Scripting Interpreter:** https://attack.mitre.org/techniques/T1059/ <br>

<br>
<br>

## **Severity**
**High**: Macro-enabled phishing attachments executing script interpreters indicate a strong likelihood of compromise.
<br>
<br>

## **Detection Type**
■ Behavior-Based Detection <br>
■ Email-to-Endpoint Correlation <br>
■ Initial Access & Execution Monitoring <br>

<br>
<br>

## **Data Sources**
### **Microsoft Sentinel**
■ `EmailAttachmentInfo` <br>
■ `DeviceProcessEvents` <br>

<br>

## **False Positives**
■ Legitimate Excel automation using macros <br>
■ Internal macro-enabled templates from trusted senders <br>
■ Developer or finance workflows spawning scripts intentionally <br>

<br>
<br>

---

## **KQL Query: Behavior-Based Macro Malware Detection**

```kusto
// Step 1: Identify macro-enabled Excel attachments delivered via email
let ExcelAttachments =
EmailAttachmentInfo
| where FileName endswith ".xls" or FileName endswith ".xlsm"
| project
    AttachmentTime = TimeGenerated,
    NetworkMessageId,
    RecipientEmailAddress,
    SenderFromAddress,
    FileName;

// Step 2: Detect Excel launched from Outlook (user opened attachment)
let ExcelLaunchedFromOutlook =
DeviceProcessEvents
| where FileName =~ "EXCEL.EXE"
| where InitiatingProcessFileName =~ "OUTLOOK.EXE"
| project
    DeviceName,
    ExcelProcessTime = TimeGenerated,
    ProcessId,
    ProcessCommandLine;

// Step 3: Detect suspicious child processes spawned by Excel (macro execution)
let SuspiciousChildProcesses =
DeviceProcessEvents
| where InitiatingProcessFileName =~ "EXCEL.EXE"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project
    DeviceName,
    ChildProcessTime = TimeGenerated,
    FileName,
    ProcessCommandLine;

// Step 4: Correlate email delivery → Excel open → macro execution
ExcelAttachments
| join kind=inner (ExcelLaunchedFromOutlook) on $left.RecipientEmailAddress == $right.DeviceName
| join kind=inner (SuspiciousChildProcesses) on DeviceName
| where ChildProcessTime between (ExcelProcessTime .. ExcelProcessTime + 10m)
| project
    AttachmentTime,
    ExcelProcessTime,
    ChildProcessTime,
    RecipientEmailAddress,
    SenderFromAddress,
    FileName,
    DeviceName,
    ProcessCommandLine
| order by ChildProcessTime desc

```

--- 
<br>
<br>

## **References**
■ Kaspersky (n.d.) Virus.MSExcel.Laroux.lh [Online]. Available at: https://threats.kaspersky.com/en/threat/Virus.MSExcel.Laroux.lh <br>

<br>
<br>

## **Author**
**Faiza Aslam**
