# Alert Title: AWS S3 Encryption Using Customer-Managed KMS Keys
<br>

## **Description**
This query detects Amazon S3 activities where **AWS KMS customer-managed keys** are used for server-side encryption. <br>
It monitors AWS CloudTrail logs for `PutBucketEncryption` and `PutObject` events from `s3.amazonaws.com` and extracts the KMS Key ID applied during encryption operations. <br>
<br>
**This helps analysts quickly**: <br>
■ Identify S3 buckets or objects encrypted with specific KMS keys <br>
■ Detect unauthorized or unexpected use of customer-managed KMS keys <br>
■ Investigate potential ransomware or data impact scenarios involving malicious re-encryption <br>
<br>
The diagram below illustrates the attack flow and the detection point:
<img width="812" height="607" alt="image" src="https://github.com/user-attachments/assets/55099d4d-7b4c-40fd-9d49-51568df5d165" />

<br>
<br>
<br>

## **Threats**
■ Malicious re-encryption of S3 objects using attacker-controlled KMS keys <br>
■ Unauthorized modification of S3 bucket encryption settings <br>
■ Potential S3 ransomware activity or data lock-in scenarios <br>

<br>
<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Impact <br>
■ Defense Evasion <br>

<br>

### **Techniques**
■ **T1486 – Data Encrypted for Impact**: https://attack.mitre.org/techniques/T1486/ <br>
■ **T1565.001 – Stored Data Manipulation: Modify Stored Data**: https://attack.mitre.org/techniques/T1565/001/ <br>

<br>
<br>

## **Severity**
**High**: Unexpected use of customer-managed KMS keys for S3 encryption may indicate active data impact, ransomware preparation, or malicious persistence.
<br>
<br>

## **Detection Type** 
■ Cloud Security Monitoring <br>
■ Data Protection & Encryption Abuse Detection <br>
■ Ransomware Early-Warning Signal <br>

<br>
<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **AWS**: `AWSCloudTrail`

<br>

## **False Positives**
■ Legitimate S3 encryption changes during infrastructure deployment <br>
■ Approved use of customer-managed KMS keys for data protection <br>
■ Automated processes applying encryption via IaC or CI/CD pipelines <br>

<br>
<br>

--- 

## **KQL Query**

```kusto

let ApprovedKms = dynamic([`Add KMS Keys Here`]);

AWSCloudTrail
| where EventSource == "s3.amazonaws.com"
| where EventName in ("PutBucketEncryption", "PutObject")
| extend rp = todynamic(RequestParameters)
| extend Rule = rp.ServerSideEncryptionConfiguration.Rule
| extend Apply = Rule.ApplyServerSideEncryptionByDefault
| extend KmsKeyId = coalesce(
        tostring(Apply.KMSMasterKeyID), tostring(rp["x-amz-server-side-encryption-aws-kms-key-id"]), tostring(rp.kmsKeyId)
)
| where isnotempty(KmsKeyId) and isnotempty(UserIdentityArn)
| where KmsKeyId !in (ApprovedKms)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), Users = make_set(UserIdentityArn) by KmsKeyId


```

--- 

<br>
<br>

## **References**
■ Kao, J. (2025) The Complexity of Detecting Amazon S3 and KMS Ransomware, Fog Security, 7th April [Blog]. Available at: https://www.fogsecurity.io/blog/how-to-detect-amazon-s3-ransomware
■ Verma, Y. (2025) Breaking Down S3 Ransomware: Variants, Attack Paths and Trend Vision One™ Defenses, Trend Micro, 18th November [Blog]. Available at: https://www.trendmicro.com/en_us/research/25/k/s3-ransomware.html
<br>
<br>
## **Author**
**Faiza Aslam**
