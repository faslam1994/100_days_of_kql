

# Alert Title: Risky User Dismissal & Compromise Actions

<br>

## **Description**
This query identifies administrative actions in Microsoft Entra ID Audit Logs where a security user has performed critical operations such as DismissUser or ConfirmAccountCompromised within the last 30 days. <br> 
It helps security teams track who confirmed account compromises or dismissed users, ensuring accountability and detecting potential misuse of privileged actions. <br>
<br>
**Key objectives**:  <br>
■  Monitor high-impact security operations  <br>
■  Identify which admin performed the action  <br>
■  Correlate suspected compromised accounts with responsible security users  <br>



<br>

## **Threats**
■ Insider misuse of privileged actions
■ Unauthorized dismissal of compromised accounts
■ Potential cover-up of account compromise

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Defense Evasion
■ Impact

<br>

### **Techniques**
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>
■ **T1098 – Account Manipulation**: https://attack.mitre.org/techniques/T1098/<br>

<br>

## **Severity**
**Mediumh**: These actions are legitimate but sensitive. If performed by unauthorized or unexpected users, they may indicate insider threats or compromised admin accounts. <br> 
<br>

## **Detection Type**
■ Audit Monitoring
■ Privileged Action Tracking

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Entra ID**: `AuditLogs`

<br>

## **False Positives**
■ Legitimate security operations by authorized personnel. <br>
■ Automated scripts performing expected account cleanup. <br>
<br>

--- 


## **KQL Query**

```kusto

let Timeframe = 30d;
AuditLogs
 |where TimeGenerated > ago(Timeframe)
|where OperationName has_any("DismissUser", "ConfirmAccountCompromised")
|extend SuspectedUser = tostring(TargetResources[0].displayName)
|extend SecurityUser = InitiatedBy.user.userPrincipalName
|where SecurityUser contains "entername"
|project TimeGenerated, OperationName, SecurityUser, SuspectedUser<img width="552" height="144" alt="image" src="https://github.com/user-attachments/assets/71f7e0ae-3aba-4542-9978-b7d526f7db49" />


```

--- 
<br>

## **References**
■ Santhanam, A. (2025) Red Hat Data Breach Exposes 21,000+ Nissan Customer Records, Medium, 29th December [Blog]. Available at: https://cybersecuritywriteups.com/red-hat-data-breach-exposes-21-000-nissan-customer-records-dd93eb2a35a3  
■ SOCRadar (2025) Dark Web Profile: ShinyHunters, SOCRadar, 18th March [Blog]. Available at: https://socradar.io/blog/dark-web-profile-shinyhunters/

<br>

## **Author**
**Faiza Aslam**
