
# Alert Title
GitLab Source Code Exfiltration via Valid Credentials


## **Description**
This query detects potential source‑code exfiltration following a successful GitLab authentication, a technique commonly seen in supply‑chain and third‑party vendor breaches. It correlates successful GitLab sign‑ins—including vendor, contractor, or third‑party accounts—with large outbound data transfers exceeding **1 GB** from the same IP address within a one‑hour window.

This behaviour mirrors the December 2025 Nissan vendor GitLab breach, where attackers used valid vendor credentials to authenticate and exfiltrate source code without deploying malware.

By focusing on **behavioural sequencing** instead of IOCs, this analytic helps identify:
- Compromised vendor or service accounts  
- Unauthorized repository cloning or bulk export activity  
- Exfiltration over legitimate encrypted channels  

This makes it especially effective for detecting **TTP‑based intrusions** that bypass traditional signature‑based defences.


## **Threats**
■ **Crimson Collective**  
■ **ShinyHunters**


## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access  
■ Persistence  
■ Exfiltration  

### **Techniques**
■ **T1078 – Valid Accounts**  
■ **T1567.002 – Exfiltration to Cloud Storage**  
■ **T1041 – Exfiltration Over C2 Channel**


## **Severity**
**High**


## **Detection Type**
■ Threat Hunting  
■ Behavioural Detection  
■ TTP‑based  


## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Entra ID**: `SigninLogs`  
■ **CommonSecurityLog** (Firewall / Proxy logs)


## **False Positives**
■ Legitimate developers performing authorised large repository clones  
■ Automated CI/CD pipelines or build agents  
■ Scheduled backups or artifact distribution tasks  

---

# **KQL Query**

```kusto

let GitLabLogins =
    SigninLogs
    | where AppDisplayName has "GitLab"
    | where ResultType == 0               // success
    | project UserPrincipalName, IPAddress, TimeGenerated, AppDisplayName;

let NetworkExfil =
    CommonSecurityLog
    | extend SentGB = round(SentBytes / 1024.0 / 1024.0 / 1024.0, 2)     // adjust: many vendors use bytes_out / outBytes
    | where SentGB > 1 
    | where DeviceAction !in~ ("deny", "blocked")
    | project SourceIP, DestinationIP, DestinationPort, TimeGenerated, SentBytes, SentGB, RequestURL;

GitLabLogins
| join kind=inner (
    NetworkExfil
    // Map IP fields to align for join. If your proxy logs show client IP as SrcIP (public),
    // this direct mapping may work; otherwise use NAT mapping from your egress firewall.
    | project IPAddress = tostring(SourceIP), TimeGenerated, SentBytes, SentGB, RequestURL, DestinationIP, DestinationPort
) on IPAddress
| where TimeGenerated1 between (TimeGenerated .. TimeGenerated + 1h)
| project UserPrincipalName, IPAddress, LoginTime=TimeGenerated, ExfilTime=TimeGenerated1,
          SentGB, RequestURL, DestinationIP, DestinationPort, AppDisplayName
```

---


## **References**
■ Santhanam, A. (2025) Red Hat Data Breach Exposes 21,000+ Nissan Customer Records, Medium, 29th December [Blog]. Available at: https://cybersecuritywriteups.com/red-hat-data-breach-exposes-21-000-nissan-customer-records-dd93eb2a35a3  
■SOCRadar (2025) Dark Web Profile: ShinyHunters, SOCRadar, 18th March [Blog]. Available at: https://socradar.io/blog/dark-web-profile-shinyhunters/


## **Author**
**Faiza Aslam**
