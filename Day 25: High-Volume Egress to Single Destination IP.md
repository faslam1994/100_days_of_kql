# Alert Title: High-Volume Egress to Single Destination IP

<br>

## **Description**
This detection highlights large outbound data transfers to a single destination IP observed in `CommonSecurityLog` over the last 30 days. It aggregates bytes sent across events by `DeviceVendor`, `DeviceProduct`, and `DestinationIP`, flags destinations exceeding **0.5 TB** of egress, and surfaces the connection count and top source IPs observed.  
Such patterns can indicate data exfiltration, misconfiguration, or unsanctioned bulk transfers.
 <br> 

This helps security teams: <br>
■ Identify potential exfiltration or shadow IT transfers  <br>
■ Prioritize high‑volume egress for triage  <br>
■ Pinpoint which internal sources contributed to the transfer  <br>
■ Focus on specific destinations for threat intel and escalation  <br>
 
<br>
Key objectives: <br>
■ Detect destinations with unusually high sent bytes <br> 
■ Correlate who/what generated the egress  <br>
■ Enable rapid scoping and response  <br>
■ Support governance of egress policies and DLP controls  <br>

<br>


<br>

## **Threats**
■ Data exfiltration to external infrastructure  <br>
■  Malicious use of legitimate services (cloud storage, file shares, pastebins)  <br>
■  Malware/operator staging or bulk transfers to C2  <br>
■  Policy bypass through unauthorized channels or encrypted tunnels  <br>
 <br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Defense Evasion <br>
■ Exfiltration  <br>
■ Command and Control  <br>
■ Collection  <br>
 <br>
<br>

### **Techniques**
■ **T1048 – Exfiltration Over Alternative Protocol:** https://attack.mitre.org/techniques/T1048/  
■ **T1041 – Exfiltration Over C2 Channel:** https://attack.mitre.org/techniques/T1041/  
■ **T1071 – Application Layer Protocol:** https://attack.mitre.org/techniques/T1071/  
■ **T1567 – Exfiltration Over Web Service:** https://attack.mitre.org/techniques/T1567/  
  <br>

<br>

## **Severity**
**High**: Sustained or aggregated outbound transfers exceeding **0.5 TB** to a single external IP within 30 days are strongly anomalous and consistent with potential data exfiltration or unsanctioned bulk movement, warranting immediate investigation.  <br> 
<br>
<br>

## **Detection Type**
■ Behavioural / Anomaly‑based Detection  <br>
■  TTP‑based   <br>
■ Exfiltration Monitoring   <br>
<br>
<br>

## **Data Sources**
### **Microsoft Sentinel**
■  `CommonSecurityLog` <br>
■ Typical fields: `DeviceVendor`, `DeviceProduct`, `SourceIP`, `DestinationIP`, `SentBytes`<br>
<br>
<br>
## **False Positives**
■ Legitimate large transfers such as backups or DR replication   <br>
■  Approved uploads to sanctioned cloud storage or CDN endpoints   <br>
■  Content/media distribution by authorized services <br>
 <br>

<br>
<br>

---

## **KQL Query**

```kusto

CommonSecurityLog
| where TimeGenerated >= ago(30d)
| summarize 
    SentTB = sum(tolong(SentBytes)) / pow(1024, 4),
    ConnCount = count(),
    SourceIP = make_set(SourceIP, 20)
  by DeviceVendor,
     DeviceProduct,
     DestinationIP
| where SentTB > 0.5
| order by SentTB desc



```

--- 

<br>


## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources <br>
<br>

## **Author**
**Faiza Aslam**
