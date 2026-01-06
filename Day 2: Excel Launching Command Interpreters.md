# Alert Title: Excel Launching Command Interpreters

<br>

## **Description**
This alert is designed to detect scenarios where EXCEL.EXE launches Windows script or command interpreters such as PowerShell, CMD, WScript, CScript, or MSHTA—together with suspicious arguments commonly linked to fileless execution or remote payload retrieval, including indicators like IEX, -EncodedCommand, DownloadString, and http/https paths. 
Attackers frequently exploit Excel VBA, Excel 4.0 (XL4) macros, and OLE/HTA‑based execution chains to run code directly in memory and pull additional malicious components from the internet. 
The recently disclosed CVE‑2025‑47174, a heap‑based buffer overflow vulnerability in Microsoft Excel, allows arbitrary code execution when a user opens a specially crafted Excel file. 
After initial compromise, adversaries often escalate their activity by leveraging script interpreters spawned from Excel to stage and execute secondary payloads. 
Immediate application of Microsoft’s security update is strongly recommended, along with continuous monitoring for abnormal Excel‑spawned processes that match the behaviors outlined in this alert.

<br>

## **Threats**
■ **Emotet**  
■ **TA551/Shathak**

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Defense Evasion <br>
■ Command and Control <br>
■ Exfiltration  <br>

<br>

### **Techniques**
■ **T1059.001 – Command and Scripting Interpreter: PowerShell**: https://attack.mitre.org/techniques/T1059/001/ <br>
■ **T1059.003 – Command and Scripting Interpreter: Windows Command Shell**: https://attack.mitre.org/techniques/T1059/003/ <br>
■ **T1059.005 – Command and Scripting Interpreter: Visual Basic**: https://attack.mitre.org/techniques/T1059/005/ <br>
■ **T1218.005 – Signed Binary Proxy Execution: MSHTA**: https://attack.mitre.org/techniques/T1218/005/ <br>
■ **T1105 – Ingress Tool Transfer**: https://attack.mitre.org/techniques/T1105/ <br>
■ **T1027 – Obfuscated/Compressed Files and Information**: https://attack.mitre.org/techniques/T1027/ <br>
■ **T1204 – User Execution**: https://attack.mitre.org/techniques/T1204/ <br>

<br>

## **Severity**
**High**: Attack chain demonstrates initial execution from malicious Excel documents leading to arbitrary code and fileless payload download/execution

<br>

## **Detection Type**
■ Threat Hunting  
■ Behavioural Detection  
■ TTP‑based  

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `DeviceProcessEvents`  

<br>

## **False Positives**
■ Legitimate automation: Internal Excel add-ins or admin scripts that invoke PowerShell/CMD to perform maintenance tasks. 
■ Business workflows: Some Business Intelligence scenarios such as Power Query or Office add-ins may fetch web content. 

<br>

--- 


## **KQL Query**

```kusto


// Source table for process creation telemetry (MDE/Defender for Endpoint)
DeviceProcessEvents
| where InitiatingProcessFileName == "EXCEL.EXE"
// Limit to script/command interpreters commonly abused post‑Excel
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
// Look for suspicious/fileless indicators in the child process command line
| where ProcessCommandLine has_any (
    "-EncodedCommand",        // Base64-encoded PowerShell payloads
    "FromBase64String",       // .NET decoding seen in PowerShell stagers
    "Invoke-Expression",      // PowerShell dynamic execution
    "IEX",                    // Short form of Invoke-Expression
    "DownloadString",         // Remote string fetch (e.g., WebClient)
    "http", "https"           // Network fetch (URLs in the command line)
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256, IsProcessRemoteSession, ProcessVersionInfoFileDescription, ProcessVersionInfoOriginalFileName, InitiatingProcessSignerType, InitiatingProcessUniqueId
| order by TimeGenerated desc

```

--- 
<br>

## **References**
■  WindowsForum (2025) Microsoft Excel CVE‑2025‑47174: Critical Remote Code Execution Vulnerability, WindowsForum, 10th June. Available at: https://windowsforum.com/threads/microsoft-excel-cve-2025-47174-critical-remote-code-execution-vulnerability.369800/
■  CounterCraft (n.d.) Analysis of an Emotet Infection via a Malicious Excel Macro, CounterCraft [Blog]. Available at: https://www.countercraftsec.com/blog/analysis-of-an-emotet-infection-via-a-malicious-excel-macro/
■ Keepnet Labs (2024) Excel XLL Add‑Ins Cause 600% Rise in Phishing Attacks: Stay Safe, Keepnet Labs, 25th November [Blog]. Available at: https://keepnetlabs.com/blog/excel-xll-add-ins-cause-600-rise-in-phishing-attacks-stay-safe"

<br>

## **Author**
**Faiza Aslam**
