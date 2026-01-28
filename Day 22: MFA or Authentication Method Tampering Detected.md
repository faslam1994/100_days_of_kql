# Alert Title: MFA or Authentication Method Tampering Detected

<br>

## **Description**
This detection identifies modifications or removal of authentication protections within Microsoft Entra ID, including disabling strong authentication, updating authentication methods, or deleting MFA factors. Attackers who compromise accounts frequently attempt to weaken or remove MFA protections to maintain persistence and prevent recovery actions. <br> 

This helps security teams: <br>
■ Detect MFA disablement or factor removal attempts <br> 
■ Identify compromised accounts attempting to bypass protections <br>
■ Monitor authentication configuration changes <br> 
■ Investigate identity defense evasion activity <br> 
<br>
Key objectives: <br>
■ Detect MFA removal or bypass attempts <br>
■ Prevent account takeover persistence <br>
■ Identify unauthorized authentication changes <br>
■ Strengthen identity security posture <br>
<br>


<br>

## **Threats**
■ Account takeover (ATO) <br>
■ Credential theft <br>
■ MFA bypass or removal <br>
■ Persistence via weakened authentication controls <br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Defense Evasion <br>
■ Credential Access <br>
■ Persistence <br>
<br>

### **Techniques**
■ **T1556 – Modify Authentication Process**: https://attack.mitre.org/techniques/T1556/  <br>
■ **T1098 – Account Manipulation**: https://attack.mitre.org/techniques/T1098/  <br>
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/  <br>

<br>

## **Severity**
**High**: Disabling or modifying authentication protections is a strong indicator of compromise or malicious persistence behaviour and should be investigated immediately. <br> 
<br>
<br>

## **Detection Type**
■ Identity Threat Detection <br>
■ Persistence Monitoring <br>
■ Defense Evasion Detection <br>
<br>
<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Entra ID**: `AuditLogs`
<br>
<br>
## **False Positives**
■ Helpdesk or IT administrators resetting MFA for users <br>
■ Legitimate device or phone replacement <br>
■ Password or authentication troubleshooting <br>
■ Automated identity lifecycle workflows <br>

<br>
<br>

---

## **KQL Query**

```kusto
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName has_any (
    "Disable strong authentication",
    "Update authentication methods",
    "Delete authentication method"
)
| project
    TimeGenerated,
    InitiatedBy,
    OperationName,
    TargetResources
| order by TimeGenerated desc



```

--- 

<br>


## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources <br>
<br>

## **Author**
**Faiza Aslam**
