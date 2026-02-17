# Alert Title: URL Clicks from Targeted Email Campaign

<br>

## **Description**

This detection correlates email-delivery telemetry with user click activity by linking `EmailEvents` and `UrlClickEvents` using `NetworkMessageId`. It scopes to messages with a specific Subject and SenderDisplayName, then returns all URL click events for those emails within the last 7 days. Use this to rapidly assess who received the target email and who clicked links within it for incident response, user outreach, and containment. <br>


<br>
Key indicators for detection: <br>
■ Identify recipients who clicked links from a suspicious/targeted email   <br>
■ Scope potential exposure** from a single campaign   <br>
■ Prioritize user notification, URL blocking, and credential reset actions   <br>
■ Feed mail hygiene and URL detonation pipelines for verdicting <br>
 <br>

<br>

<br>
<br>
<br>


## **Threats**
■ Phishing leading to credential theft    <br>
■ Malware delivery via embedded links (drive‑by, downloaders)    <br>
■ Business email compromise (BEC) lures    <br>
■ Watering hole or redirection to look‑alike portals  <br>
  <br>


<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access  <br>
■ Credential Access  <br>
■ Collection <br>


<br>
  
     
<br>

### **Techniques**

 **T1566 – Phishing:**  https://attack.mitre.org/techniques/T1566/  
■ **T1566.002 – Spearphishing Link:** https://attack.mitre.org/techniques/T1566/002/  
■ **T1056 – Input Capture:** https://attack.mitre.org/techniques/T1056/  
■ **T1204 – User Execution:** https://attack.mitre.org/techniques/T1204/



<br>

## **Severity**
**Medium**: User clicks on links from a scoped campaign represent credible risk of credential theft or malware delivery, but require URL verdicting and host/user context to confirm impact.   <br>

<br>

## **Detection Type** 
■ Behavioral Detection  <br>
■ Campaign Scoping / Impact Assessment    <br>
■ TTP-Based  <br>



<br>

## **Data Sources**
### **Microsoft Sentinel** 
■ **Microsoft XDR Telemetry**: `EmailEvents` `URLClickEvents`  <br>

<br>

## **False Positives**
■ Legitimate internal campaigns or training emails with tracked links  <br>
■ Marketing/newsletter messages with benign tracking URLs  <br>
■ Security awareness phishing simulations <br>
<br>

<br>

--- 


## **KQL Query**

```kusto

let lookback = ago(7d);
let Email = EmailEvents
| where TimeGenerated > lookback
| where Subject contains "Enter Subject"
| where SenderDisplayName contains "Enter Name"
| distinct NetworkMessageId;
UrlClickEvents
| where TimeGenerated > lookback
| where NetworkMessageId has_any (Email)



 

```

--- 
<br>

## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources

<br>
<br>

## **Author**
**Faiza Aslam**
