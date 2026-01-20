# Alert Title: Whale-Phishing Attack Detection Targeting Executives
<br>

## **Description**
A whale-phishing attack targets **high-value individuals** within an organization—typically C-suite executives or senior leadership—who possess sensitive information or authority over financial and strategic decisions. <br>
<br>
This detection identifies **executive-focused phishing attempts** by monitoring emails sent to predefined “whale” users from external senders that exhibit common phishing characteristics such as urgency, financial lures, suspicious links, or high-risk attachments. <br>
<br>
**This dectection helps analysts quickly**: <br>
■ Identify phishing campaigns targeting executives and decision-makers <br>
■ Detect early stages of ransomware or BEC attacks <br>
■ Reduce risk of reputational damage and financial loss <br>

<br>
<br>

## **Threats**
■ Whale-phishing and executive impersonation <br>
■ Ransomware delivery via malicious attachments <br>
■ Credential harvesting and account takeover <br>
■ Business Email Compromise (BEC) <br>

<br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Credential Access <br>
■ Impact <br>

<br>

### **Techniques**
■ **T1566.001 – Phishing: Spearphishing Attachment:** https://attack.mitre.org/techniques/T1566/001/ <br>
■ **T1566.002 – Phishing: Spearphishing Link:**  https://attack.mitre.org/techniques/T1566/002/ <br>
■ **T1486 – Data Encrypted for Impact:**  https://attack.mitre.org/techniques/T1486/ <br>

<br>
<br>

## **Severity**
**High**: Whale-phishing attacks target users with authority, access to sensitive data, and a higher likelihood of paying ransoms to avoid reputational or business damage.
<br>
<br>

## **Detection Type**
■ Executive Threat Monitoring <br>
■ Email Threat Detection <br>
■ Phishing & Ransomware Pre-Infection Detection <br>

<br>
<br>

## **Data Sources**
### **Microsoft Sentinel**
■ `EmailEvents` <br>
■ `EmailUrlInfo` <br>
■ `EmailAttachmentInfo` <br>

<br>

## **False Positives**
■ Legitimate external communications with executives <br>
■ Financial or legal emails using urgent language <br>
■ Approved third-party file sharing or billing systems <br>

<br>
<br>

---

## **KQL Query**

```kusto
// Step 1: Define executive (whale) users, this can be defined through a watchlist too.
let WhaleUsers = dynamic(["ceo@company.com", "cfo@company.com", "coo@company.com", "cio@company.com", "ciso@company.com"]);

// Step 2: Detect suspicious emails sent to whale users
EmailEvents
| where RecipientEmailAddress in (WhaleUsers)
| where SenderFromDomain !endswith "company.com"
| where DeliveryAction == "Delivered"
| where Subject has_any ("urgent", "immediate", "payment", "wire", "invoice", "confidential", "action required")
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, SenderFromDomain, Subject, NetworkMessageId

| join kind=leftouter (
    // Step 3: Identify suspicious phishing URLs
    EmailUrlInfo
    | where Url has_any ("login", "verify", "secure", "update", "account")
    | project NetworkMessageId, Url) on NetworkMessageId

| join kind=leftouter (
    // Step 4: Identify high-risk attachments
    EmailAttachmentInfo
    | where FileType in ("zip", "iso", "xls", "xlsm", "html", "pdf")
    | project NetworkMessageId, FileName, FileType) on NetworkMessageId
| order by TimeGenerated desc

```

--- 
<br>
<br>

## **References**
■  Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources


<br>
<br>

## **Author**
**Faiza Aslam**
