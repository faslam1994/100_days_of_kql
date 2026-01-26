# Alert Title: Risky Users by City (Medium/High User Risk Events)

<br>

## **Description**
This detection identifies users in Microsoft Entra ID who have triggered **Medium or High-risk user events** within the last 30 days.  
By joining `AADUserRiskEvents` with organisational identity data from `IdentityInfo`, this alert provides a **city-level breakdown** of where risky user activity is occurring.

<br>
This helps security teams:  
■ Identify concentrations of elevated-risk identity behaviour  <br>
■ Detect locations with persistent Medium/High-risk user activity  <br>
■ Prioritise investigations based on geographic patterns  <br>

<br>

**Key objectives:**  
■ Compromised user accounts  <br>
■ Credential theft and account takeover attempts  <br>
■ Sign-ins from malicious or suspicious IP addresses  <br>
■ Unusual or anomalous sign-in behaviour  <br>


<br>

## **Threats**
■ Compromised user accounts  <br>
■ Credential theft and account takeover attempts  <br>
■ Sign‑ins from malicious or unusual IP addresses   <br>
■ Impossible travel or anomalous geolocation activity  <br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**

■ Credential Access  <br>
■ Initial Access <br> 
■ Defense Evasion  <br>

<br>

### **Techniques**
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>
■ **T1110 – Brute Force**: https://attack.mitre.org/techniques/T1110/  <br>
■ **T1606 – Forge Web Credentials**: https://attack.mitre.org/techniques/T1606/  <br>

<br>

## **Severity**
**Medium**: Indicates elevated user risk levels which may be early indicators of identity compromise. If correlated with repeated detections or anomalous behaviour, the severity may warrant escalation.  <br>
<br>

## **Detection Type**
■ User Risk Analytics  <br>
■ Identity Threat Detection  <br>
■ Behavioural Analytics  <br>

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Entra ID**: `AADUserRiskEvents`  `IdentityInfo`  
<br>

## **False Positives**
■ Users signing in from VPN or remote access tools  <br>
■ Employees travelling between regions  <br>
■ Automated identity workflows or governance actions  <br>
<br>
<br>

---

## **KQL Query**

```kusto
let IdentityData =
IdentityInfo
| project AccountUPN, Department, City;

AADUserRiskEvents
| where TimeGenerated > ago(30d)
| where RiskLevel in~ ("Medium","High")
| join kind=leftouter IdentityData on $left.UserPrincipalName == $right.AccountUPN
| summarize RiskyUsers = dcount(UserPrincipalName) by City
| render piechart



```

--- 

<br>


## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources?view=microsoft-fabric <br>
■ Microsoft (n.d.) Microsoft Entra ID risk detections [Online]. Available at: https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks  <br>

## **Author**
**Faiza Aslam**
