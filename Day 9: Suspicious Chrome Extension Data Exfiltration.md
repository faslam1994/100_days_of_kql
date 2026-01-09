
# Alert Title: Suspicious Chrome Extension Data Exfiltration

<br>

## **Description**
A large-scale campaign involving two malicious Chrome extensions that use ChatGPT has been discovered, impacting over 900,000 users. These extensions masqueraded as legitimate AI productivity tools to gain user trust. Once installed, they requested user permissions to collect anonymized analytics. Once the user had agreed, the malicious Chrome extensions harvested entire ChatGPT and DeepSeek conversation histories, along with browsing activity. The stolen data was transmitted to remote servers every 30 minutes. The campaign was uncovered by the OX Research team during a routine threat analysis.  <br>
<br>
This technique, known as Prompt Poaching, involves capturing users’ AI-generated prompts and responses to steal sensitive information, which can then be exploited for corporate espionage, identity theft, or other malicious purposes. Legitimate extensions like Similarweb have also been observed engaging in extensive data collection, highlighting broader privacy and security concerns in browser extensions. <br>
<br>
Key risk indicators for detection: <br>
■  Chrome/Edge extensions interacting with AI platforms. <br>
■  Extensions not hosted by Google infrastructure. <br>
■  Potential session scraping or API abuse. <br>
■  Silent background exfiltration behaviour. <br>
<br>
<br>
<img width="881" height="421" alt="image" src="https://github.com/user-attachments/assets/edafa4ec-b651-4585-b57a-287b6d347946" />

<br>
<br>
<br> 

## **Threats**
■ **APT Groups: APT28, APT41, Lazarus**

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Exfiltration <br>
■ Command and Control <br>
■ Credential Access <br>
  
     
<br>

### **Techniques**
■ **T1056.007 – Input Capture: Web Browser Input**: https://attack.mitre.org/techniques/T1056/007/ <br>
■ **T1566 – Phishing**: https://attack.mitre.org/techniques/T1566/ <br>
■ **T1071.001 – Application Layer Protocol: Web Protocols**: https://attack.mitre.org/techniques/T1071/001/ <br>
■ **T1041 – Exfiltration Over C2 Channel**: https://attack.mitre.org/techniques/T1041/ <br>

<br>

## **Severity**
**High**: By impersonating legitimate extensions, users were tricked into installing malware, which increases the likelihood of compromise. This can lead to complete AI conversation data and browsing activity stolen, which may include sensitive, confidential, or proprietary information.

<br>

## **Detection Type** 
■ Behavioural Detection  <br>
■ TTP‑based  <br>

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `DeviceNetworkEvents` `DeviceProcessEvents`

<br>

## **False Positives**
■  Legitimate productivity extensions interacting with ChatGPT/AI Tools <br>
■  Developer tools or automation extensions <br>
■  Enterprise-approved browser plugins <br>

<br>

--- 


## **KQL Query**

```kusto

let timeframe = 24h;
let AI_Sites = dynamic([
    "chat.openai.com",
    "chatgpt.com",
    "deepseek.com"
]);

DeviceNetworkEvents
| where TimeGenerated >= ago(timeframe)
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe")
| where RemoteUrl has_any (AI_Sites)
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated >= ago(timeframe)
    | where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe")
    | where ProcessCommandLine has "chrome-extension://"
) on DeviceId
| where RemoteUrl !endswith ".google.com"
| summarize
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    AI_Domains=make_set(RemoteUrl),
    ExtensionCommands=make_set(ProcessCommandLine),
    ConnectionCount=count()
by DeviceName, AccountName
| order by ConnectionCount desc


```

--- 
<br>

## **References**
■ Burt, J. (2025) Widely Used Malicious Extensions Steal ChatGPT, DeepSeek Conversations, Security Boulevard, 30th December [Blog]. Available at: https://securityboulevard.com/2025/12/widely-used-malicious-extensions-steal-chatgpt-deepseek-conversations/ <br>
■ Ćemanović, A. (2025) Malicious Chrome extensions with 900,000 users steal AI chats, Cyber Insider, 30th December [Blog]. Available at: https://cyberinsider.com/malicious-chrome-extensions-with-900000-users-steal-ai-chats <br>

<br>

## **Author**
**Faiza Aslam**
