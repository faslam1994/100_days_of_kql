

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
■ Insider misuse of privileged actions <br>
■ Unauthorized dismissal of compromised accounts <br>
■ Potential cover-up of account compromise <br>

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Defense Evasion <br>
■ Impact <br>

<br>

### **Techniques**
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>
■ **T1098 – Account Manipulation**: https://attack.mitre.org/techniques/T1098/<br>

<br>

## **Severity**
**Medium**: These actions are legitimate but sensitive. If performed by unauthorized or unexpected users, they may indicate insider threats or compromised admin accounts. <br> 
<br>

## **Detection Type**
■ Audit Monitoring <br>
■ Privileged Action Tracking <br>

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
|project TimeGenerated, OperationName, SecurityUser, SuspectedUser

```

--- 
<br>

## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources?view=microsoft-fabric

<br>

## **Author**
**Faiza Aslam**
