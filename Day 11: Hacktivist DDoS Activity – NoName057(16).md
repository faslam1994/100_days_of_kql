

# Alert Title: Hacktivist DDoS Activity – NoName057(16)

<br>

## **Description**
In late December 2025, France’s national postal service La Poste and its banking subsidiary La Banque Postale were hit by a large-scale distributed denial-of-service (DDoS) cyberattack, significantly disrupting online postal, parcel tracking, and digital banking services during the peak Christmas season. <br>
The attack began on 22 December 2025, overwhelming key public-facing applications, including the main website, mobile applications, and secure services such as Digiposte and digital identity systems. Online parcel tracking and electronic payment functions were inaccessible, though physical postal operations and offline banking continued with degraded capabilities. No evidence has been reported of customer data compromise, as the attack focused on service availability. <br>
<br>
Key risk indicators for detection: <br>
■ Excessive or anomalous traffic patterns to public web services (HTTP/S). <br>
■ Unexpected service outages or unavailability correlated with high request rates. <br>
■ Spike in SYN/ICMP/UDP traffic from distributed sources. <br>
<br>
<br> 

## **Threats**
■ **State-aligned Hacktivist Group: NoName057(16)** <br>

<br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Impact <br>
■ Denial of Service <br>
■ Command and Control (traffic orchestration) <br>
  
     
<br>

### **Techniques**
■ **T1499 – Endpoint Denial of Service**: https://attack.mitre.org/techniques/T1499/  <br>
■ **T1608 – DDoS: Application Layer**: https://attack.mitre.org/techniques/T1608/  <br>
■ **T1071.001 – Application Layer Protocol**: Web Protocols: https://attack.mitre.org/techniques/T1071/001/ <br>

<br>
<br>

## **Severity**
**High**: The attack occurred during a peak operational period significantly impacting the availabity of postal service. This resulted in impacting millions of customers’ ability to track parcels, use banking services, and conduct online transactions.

<br>
<br>

## **Detection Type** 
■ Behavioural Detection  <br>
■ TTP‑based  <br>

<br>
<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `DeviceNetworkEvents` <br>

<br>
<br>

## **False Positives**
■ High legitimate traffic due to events or flash sales <br>
■ Internal load testing or scheduled stress tests <br>
■ Misconfigured automated monitoring tools triggering alerts <br>

<br>
<br>

---
## **KQL Query**

```kusto

let timeframe = 24h;
let timeBin = 5m;

// Baseline for normal traffic
let baseline =
DeviceNetworkEvents
| where TimeGenerated between (ago(timeframe) .. ago(1h))
| where RemotePort == 443
| summarize
    AvgReq = avg(1),
    StdDevReq = stdev(1)
by bin(TimeGenerated, timeBin), DeviceName;

// Current traffic window
DeviceNetworkEvents
| where TimeGenerated >= ago(1h)
| where RemotePort == 443
| summarize
    RequestCount = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    TotalBytes = sum(TotalBytes)
by bin(TimeGenerated, timeBin), DeviceName
| join kind=leftouter baseline on DeviceName
| where
    RequestCount > (AvgReq + (StdDevReq * 5))
    or UniqueSourceIPs > 300
| extend
    AttackConfidence = case(
        RequestCount > 20000 and UniqueSourceIPs > 500, "High",
        RequestCount > 10000 and UniqueSourceIPs > 300, "Medium",
        "Low"
    )
| project
    TimeGenerated,
    DeviceName,
    RequestCount,
    UniqueSourceIPs,
    TotalBytes,
    AttackConfidence
| order by RequestCount desc



```

--- 
<br>
<br>

## **References**
■ Dayanç , S.E (2025) Cyberattack against La Poste: the pro-Russian group NoName057 claims responsibility for the attack, Anadolu Agency, 24th December [News]. Available at: https://www.aa.com.tr/fr/monde/cyberattaque-contre-la-poste-le-groupe-prorusse-noname057-revendique-l-attaque/3779497  <br>
■ Pearson, E. (2025) French postal services disrupted after cyber-attack, The Local, 23rd December [Blog]. Available at: https://www.thelocal.fr/20251223/french-postal-services-disrupted-after-cyber-attack  <br>
■ Muncaster, P. (2025) La Poste Still Offline After Major DDoS Attack,  InfoSecurity, 24th December [Blog]. Available at: https://www.infosecurity-magazine.com/news/la-poste-still-offline-after-major/ <br>
 <br>
<br>

## **Author**
**Faiza Aslam**
