# Alert Title: Antivirus Scan Activity Monitoring

<br>

## **Description**
This analytic identifies antivirus scanning activity on an endpoint by monitoring events generated in the DeviceEvents table. It detects when a device initiates, completes, or cancels an antivirus scan and extracts additional metadata, including scan type and the user who initiated the action. <br>
This allows security teams to verify whether antivirus scans were triggered by expected processes or users, investigate unexpected or manual scan activity, and support audit and compliance requirements around endpoint protection operations. <br>
<br>
**Key objectives**:  <br>
■ Monitor antivirus scanning activity on endpoints <br>
■ Identify who initiated or cancelled a scan <br>
■ Provide visibility into scan types and outcomes <br>
■ Support investigations into unusual or unexpected scan behaviour <br>



<br>

## **Threats**
■ Unauthorized manual triggering or cancellation of antivirus scans <br>
■ Attempts to hide malicious activity via deliberate scan interruption <br>
■ Potential misuse of privileged accounts to suppress or bypass AV protections <br>

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Defense Evasion <br>
■ Execution <br>

<br>

### **Techniques**
■ **T1562 – Impair Defenses**: https://attack.mitre.org/techniques/T1562/  <br>
■ **T1204 – User Execution**: https://attack.mitre.org/techniques/T1204/<br>

<br>

## **Severity**
**Low**: Antivirus scans are generally benign; however, repeated cancellations, unexpected user‑initiated scans, or scans triggered by unusual processes may indicate evasion attempts or misuse requiring investigation. <br> 
<br>

## **Detection Type**
■  Endpoint Monitoring <br>
■  Behavioural Visibility <br>

<br>

## **Data Sources**
### **Microsoft Defender XDR** 
■  `DeviceEvents`

<br>

## **False Positives**
■ Routine antivirus scans initiated by system processes  <br>
■ Scheduled scans automatically triggered by endpoint protection configurations  <br>
■ Expected manual scans triggered during IT support or maintenance <br>
<br>
<br>

--- 


## **KQL Query**

```kusto


DeviceEvents
| where ActionType has_any ("AntivirusScan", "AntivirusScanCompleted", "AntivirusScanCancelled")
| where DeviceName contains "Enter DeviceName Here"
| extend AdditionalFields = parse_json(AdditionalFields)
| extend ScanType = AdditionalFields["ScanTypeIndex"],
         StartedBy = AdditionalFields["User"]
| project Timestamp, DeviceId, DeviceName, ActionType, ScanType, StartedBy


```

--- 
<br>

## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources?view=microsoft-fabric

<br>

## **Author**
**Faiza Aslam**
