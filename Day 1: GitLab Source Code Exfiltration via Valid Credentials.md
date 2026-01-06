
# Alert Title
GitLab Source Code Exfiltration via Valid Credentials

<br>

## **Description**
This query detects potential source‑code exfiltration following a successful GitLab authentication, a technique commonly seen in supply‑chain and third‑party vendor breaches. It correlates successful GitLab sign‑ins—including vendor, contractor, or third‑party accounts—with large outbound data transfers exceeding **1 GB** from the same IP address within a one‑hour window.

This behaviour mirrors the December 2025 Nissan vendor GitLab breach, where attackers used valid vendor credentials to authenticate and exfiltrate source code without deploying malware.

By focusing on **behavioural sequencing** instead of IOCs, this analytic helps identify:
- Compromised vendor or service accounts  
- Unauthorized repository cloning or bulk export activity  
- Exfiltration over legitimate encrypted channels  

This makes it especially effective for detecting **TTP‑based intrusions** that bypass traditional signature‑based defences.

<br>

## **Threats**
■ **Crimson Collective**  
■ **ShinyHunters**

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access  
■ Persistence  
■ Exfiltration  

<br>

### **Techniques**
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>
■ **T1567.002 – Exfiltration to Cloud Storage**: https://attack.mitre.org/techniques/T1567/002/ <br>
■ **T1041 – Exfiltration Over C2 Channel**: https://attack.mitre.org/techniques/T1041/ <br>

<br>

## **Severity**
**High**: Detects large‑scale source‑code exfiltration using valid credentials, a pattern commonly observed in high‑severity incidents involving IP theft and supply‑chain compromise.

<br>

## **Detection Type**
■ Threat Hunting  
■ Behavioural Detection  
■ TTP‑based  

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Entra ID**: `SigninLogs`  
■ **CommonSecurityLog**: Firewall / Proxy logs

<br>

## **False Positives**
■ Legitimate developers performing authorised large repository clones  
■ Automated CI/CD pipelines or build agents  
■ Scheduled backups or artifact distribution tasks  

<br>

--- 


## **KQL Query**

```kusto

// Subquery: successful GitLab sign-ins from Entra ID (limit to successes and essential fields)
let GitLabLogins =
    SigninLogs
    | where AppDisplayName has "GitLab"                    // filter to GitLab app sign-ins (adjust name if self-hosted)
    | where ResultType == 0                                // success only
    | project UserPrincipalName, IPAddress, TimeGenerated, AppDisplayName;

// Subquery: large outbound transfers from firewall/proxy telemetry (CommonSecurityLog)
let NetworkExfil =
    CommonSecurityLog
    | extend SentGB = round(SentBytes / 1024.0 / 1024.0 / 1024.0, 2)   // human-readable GB for triage
    | where SentGB > 1                                                 // threshold: > 1 GB (tune per environment)
    | where DeviceAction !in~ ("deny", "blocked")                      // exclude unsuccessful egress
    | project SourceIP, DestinationIP, DestinationPort, TimeGenerated, SentBytes, SentGB, RequestURL;

// Correlate successful GitLab logins with large outbound transfers from the same IP within 1 hour
GitLabLogins
| join kind=inner (
    NetworkExfil
    | project IPAddress = tostring(SourceIP), TimeGenerated, SentBytes, SentGB, RequestURL, DestinationIP, DestinationPort
) on IPAddress
| where TimeGenerated1 between (TimeGenerated .. TimeGenerated + 1h)   // sequence window: network event within 1h of login
| project UserPrincipalName, IPAddress, LoginTime = TimeGenerated, ExfilTime = TimeGenerated1, SentGB, RequestURL, DestinationIP, DestinationPort, AppDisplayName

```

--- 
<br>

## **References**
■ Santhanam, A. (2025) Red Hat Data Breach Exposes 21,000+ Nissan Customer Records, Medium, 29th December [Blog]. Available at: https://cybersecuritywriteups.com/red-hat-data-breach-exposes-21-000-nissan-customer-records-dd93eb2a35a3  
■ SOCRadar (2025) Dark Web Profile: ShinyHunters, SOCRadar, 18th March [Blog]. Available at: https://socradar.io/blog/dark-web-profile-shinyhunters/

<br>

## **Author**
**Faiza Aslam**
