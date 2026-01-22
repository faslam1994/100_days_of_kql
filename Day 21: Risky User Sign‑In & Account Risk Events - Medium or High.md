# Alert Title: Risky User Sign‑In & Account Risk Events (Medium/High)

<br>

## **Description**
This detection identifies users in Microsoft Entra ID who have triggered **Medium or High-risk user events** within the last 30 days.  
It leverages the `AADUserRiskEvents` table to surface suspicious sign-ins, risky IP addresses, anomalous locations, and associated MITRE techniques.  
<br>
This helps security teams:  
■ Identify users with elevated risk levels  <br>
■ Uncover anomalous sign-in patterns, risky behaviour, or potential compromise  <br>
■ Correlate risk reasons, IPs, and geolocations to strengthen investigation  <br>
<br>

**Key objectives:**  
■ Detect users with repeated Medium/High user risk events  <br>
■ Aggregate risk event details into a single analyst-friendly view  <br>
■ Enable rapid triage by exposing IPs, user agents, MITRE tags, and geo information  <br>

<br>

## **Threats**
■ Compromised user accounts  <br>
■ Credential theft and account takeover attempts  <br>
■ Sign‑ins from malicious or unusual IP addresses   <br>
■ Impossible travel or anomalous geolocation activity  <br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Credential Access  
■ Initial Access  
■ Defense Evasion  

<br>

### **Techniques**
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>
■ **T1110 – Brute Force**: https://attack.mitre.org/techniques/T1110/  <br>
■ **T1606 – Forge Web Credentials**: https://attack.mitre.org/techniques/T1606/  <br>
<br>

## **Severity**
**Medium**: These detections highlight elevated-risk behaviour that may indicate early stages of account compromise.  <br>
If repeated or combined with high‑risk sign‑ins, this may escalate to an active compromise scenario.  <br>
<br>

## **Detection Type**
■ User Risk Analytics  
■ Identity Threat Detection  
■ Sign‑In Behavioural Anomaly Detection  
<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Entra ID**: `AADUserRiskEvents`  
<br>

## **False Positives**
■ Legitimate sign-ins from VPN or remote access software  <br>
■ Users travelling internationally  <br>
■ Authentication behaviour from automated systems or identity governance workflows  <br>
<br>

---

## **KQL Query**

```kusto
AADUserRiskEvents
|where TimeGenerated > ago(30d)
|where RiskLevel in~ ('Medium', 'High')
| mv-apply RiskReasons = parse_json(AdditionalInfo) on (summarize info = make_bag(pack(tostring(RiskReasons.Key), RiskReasons.Value)))
| extend loc = parse_json(Location)
| evaluate bag_unpack(loc)      
| evaluate bag_unpack(info)
|project-away Location, AdditionalInfo
| summarize users=make_set(UserPrincipalName), userIds=make_set(UserId), IPAddresses=make_set(IpAddress), riskEventTypes=make_set(RiskEventType), riskLevels=make_set(RiskLevel), riskStates=make_set(RiskState), riskDetails=make_set(RiskDetail), detectionTiming=make_set(DetectionTimingType), sources=make_set(Source), tokenIssuerTypes=make_set(TokenIssuerType), correlationIds=make_set(CorrelationId), requestIds=make_set(RequestId), operationNames=make_set(OperationName), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated), cities=make_set(city), states=make_set(state), countries=make_set(countryOrRegion), userAgents=make_set(userAgent), mitre=make_set(mitreTechniques), riskReasons_arrays=make_set(riskReasons) by UserDisplayName
| order by lastSeen desc


```

--- 

<br>


## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources?view=microsoft-fabric <br>
■ Microsoft (n.d.) Microsoft Entra ID risk detections [Online]. Available at: https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks  <br>

## **Author**
**Faiza Aslam**
