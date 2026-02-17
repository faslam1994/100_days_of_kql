# Alert Title: SSH Traffic to Public IPs

<br>

## **Description**
This content identifies endpoints that established (or attempted) network connections to public IPs over SSH (TCP/22) in the last 90 days, using Microsoft Defender XDR’s `DeviceNetworkEvents`. 
It includes the action type (allow/block), device name, remote IP/URL, and the initiating process/account context to support triage and accountability.

<br>
Key indicators for detection: <br>
■ Visibility of SSH usage egressing to the Internet. <br>
■ Policy Enforcement such as SSH usage only permitted via bastions or VPN. <br>
■ Detection of potential brute force activity, misconfiguration, or unauthorized remote management. <br>
■ Separation of duties e.g., distinguishing developer Git-over-SSH traffic vs. administrative SSHs. <br>

<br>

<br>
<br>
<br>


## **Threats**
■  Unauthorized remote access to external systems or compromised infrastructure. 
■ Exfiltration or tunneling via SSH channels. 
■ Credential abuse (stolen keys/credentials) to reach external footholds. 
■ Malware staging or operator-controlled command execution over SSH. 


<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Lateral Movement <br>
■ Credential Access <br>
■ Exfiltration <br>
■ Command and Control<br>

<br>
  
     
<br>

### **Techniques**
■ **T1021.004 Remote Services: SSH**:  https://attack.mitre.org/techniques/T1021/004/  <br>
■ **T1078 Valid Accounts**:  https://attack.mitre.org/techniques/T1078/  <br>
■ **T1110 Brute Force**:  https://attack.mitre.org/techniques/T1110/  <br>
■ **T1046 Network Service Discovery**:  https://attack.mitre.org/techniques/T1046/  <br>
■ **T1048 Exfiltration Over Alternative Protocol**: https://attack.mitre.org/techniques/T1048/<br>


<br>

## **Severity**
**Medium:** SSH connections to public IPs can indicate risky or unauthorized remote access, but they also commonly occur for legitimate administrative or developer activity <br>

<br>

## **Detection Type** 
■ Behavioral Detection
■ Audit / Change Monitoring (Network Egress Policy)
■ TTP-Based



<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `DeviceNetworkEvents` `SigninLogs`

<br>

## **False Positives**
■ Developer workflows using Git over SSH (e.g., `github.com`, `gitlab.com`, `bitbucket.org`). <br>
■ Approved bastion hosts / jump boxes (documented allowlist).  <br>
■ Automated jobs (backup/sync/DevOps) legitimately using SSH/SCP/SFTP.  <br>
■ Network/security team administrative access during approved change windows.<br>

<br>

--- 


## **KQL Query**

```kusto


DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteIPType == "Public"
| where RemotePort == 22
| project TimeGenerated, ActionType, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountUpn, InitiatingProcessAccountName, InitiatingProcessCommandLine


 

```

--- 
<br>

## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources

<br>
<br>

## **Author**
**Faiza Aslam**
