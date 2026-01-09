
# Alert Title: High-Volume Requests to Webhook or Form URIs

<br>

## **Description**
CVE-2026-21858 (“Ni8mare”) is a maximum-severity (CVSS 10.0) vulnerability in the n8n workflow automation platform that allows an attacker to craft HTTP requests to a vulnerable webhook endpoint which leads to arbitrary file read and potentially full remote code execution on the server.

Key risk indicators for detection: <br>
■  Unusual use of webhook/form endpoints. <br>
■  Requests that return sensitive files (e.g., database, config files). <br>
■  Failed or unusual application responses. <br>
■  Unexpected sources scanning or hitting form endpoints. <br>
<br>

## **Threats**
■ **No current threat groups associated with this vulnerability yet.**

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Exploitation <br>
  
 
<br>

### **Techniques**
■ **T1190 – Exploit Public-Facing Application**: https://attack.mitre.org/techniques/T1190/ <br>
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>
■ **T1059 – Command and Script Execution**: https://attack.mitre.org/techniques/T1059/  <br>

<br>

## **Severity**
**High**: Detects high traffic or potentially anomalous access to suspected workflow automation webhook/form endpoints that could indicate exploitation of CVE-2026-21858 (Ni8mare).

<br>

## **Detection Type** 
■ Behavioural Detection  <br>
■ TTP‑based  <br>

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `AppServiceHTTPLogs`

<br>

## **False Positives**
■  Legitimate webhook integrations <br>
■  High-traffic public forms  <br>
■  Monitoring and health probes  <br>
■  Load testing or CI/CD activity <br>
■  CDN / proxy IP behavior <br>

<br>

--- 


## **KQL Query**

```kusto

let timeframe = 30d;
AppServiceHTTPLogs
| where TimeGenerated >= ago(timeframe)
| where CsUriStem  has "/webhook" or CsUriStem has "/form"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), RequestURICount = count(), distinctIPs = dcount(CIp), IP = make_set(CIp), ComputerName = make_set(ComputerName), HTTPStatus = make_set(ScStatus), URIQuery = make_set(CsUriQuery), Usernames = make_set(CsUsername), Referer = make_set(Referer), Result = make_set(Result), Cookie = make_set(Cookie), Method = make_set(CsMethod)
by CsUriStem
| where RequestURICount > 10 or distinctIPs > 10
| order by RequestURICount desc


```

--- 
<br>

## **References**
■ SOCRadar (2026) Ni8mare Flaw in n8n: What Defenders Need to Know About CVE-2026-21858, SOCRadar, 8th January [Blog]. Available at: https://socradar.io/blog/ni8mare-flaw-n8n-cve-2026-21858/

<br>

## **Author**
**Faiza Aslam**
