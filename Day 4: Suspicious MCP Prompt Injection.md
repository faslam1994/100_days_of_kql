

# Alert Title: Suspicious MCP Prompt Injection

<br>

## **Description**
This query detects potential Model Context Protocol (MCP) abuse and prompt‑injection activity by identifying suspicious LLM sampling requests followed by abnormal response behavior. 
It flags connections to MCP or LLM service endpoints that include known prompt‑injection markers such as system instructions, role‑override language, hidden characters, or encoded content. 
The detection then correlates these requests with unusually large or frequent responses, which may indicate hidden instructions, unauthorized tool invocation, or data exfiltration through AI services. 
By combining content‑based indicators with behavioral anomalies, the query identifies attacks that bypass traditional malware‑based detections. This technique aligns with emerging Shadow AI threats where attackers exploit trusted AI integrations to manipulate model behavior or extract sensitive data.

<br>

## **Threats**
■ **Kimsuky**  

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access  
■ Persistence  
■ Exfiltration  

<br>

### **Techniques**
■ **T1567 – Exfiltration Over Web Services:** https://attack.mitre.org/techniques/T1567/  <br>
■ **T1071.001 – Application Layer Protocol:** Web Protocols (HTTPS): https://attack.mitre.org/techniques/T1071/001/  <br>
■ **T1027 – Obfuscated/Compressed Files and Information:** https://attack.mitre.org/techniques/T1027/  <br>
■ **T1090 – Proxy:** https://attack.mitre.org/techniques/T1090/  <br>
<br>

## **Severity**
**Medium–High**: Exploits trusted AI integrations to enable covert instruction hijacking or data exfiltration, with escalation to high when privileged accounts, sensitive data, or repeated abnormal sampling patterns are observed.

<br>

## **Detection Type** 
■ Behavioural Detection  <br>
■ TTP‑based  

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `DeviceNetworkEvents`  

<br>

## **False Positives**
■ Sanctioned MCP servers or AI tools may naturally generate higher token usage or large responses. <br>
■ Advanced prompt engineering can resemble injection patterns without malicious intent. <br>
■ Automated AI workflows may produce large response payloads or frequent requests in short time windows. <br>
■ Developers or data scientists may legitimately use long prompts, Base64 encoding, or repeated sampling during model testing. <br>

<br>

--- 


## **KQL Query**

```kusto

// List of known suspicious MCP / LLM server domains
let MCP_Domains = dynamic([
    "unit42-mcp-malicious.example", "modelcontextprotocol.io", "api.mcp", "mcp-sampling-service"
]);

// Pattern markers in requests
let InjectionPatterns = dynamic([
    "[INST]", "System:", "You are now", "Base64", "\u200B"  // zero-width space
]);

// Detect suspicious MCP requests
let SuspiciousRequests =
    DeviceNetworkEvents
    | where RemoteUrl has_any (MCP_Domains)
    | where ActionType == "ConnectionSuccess"
    | where ProcessCommandLine has_any (InjectionPatterns)
    | extend TokenCount = strlen(ProcessCommandLine)  // crude token proxy
    | project TimeGenerated, DeviceName, AccountName, RemoteUrl, RemoteIP, InitiatingProcessFileName, ProcessCommandLine, TokenCount;

// Detect large or frequent responses
let SuspiciousResponses =
    DeviceNetworkEvents
    | where RemoteUrl has_any (MCP_Domains)
    | where SentBytes > 5000000   // >5 MB responses
    | summarize RequestCount = count(), TotalBytes = sum(SentBytes) by DeviceName, AccountName, RemoteIP, bin(TimeGenerated, 5m)
    | where RequestCount > 5 or TotalBytes > 25000000  // frequent sampling or large response
    | project TimeGenerated, DeviceName, AccountName, RemoteIP, RequestCount, TotalBytes;

// Correlate suspicious requests with responses
SuspiciousRequests
| join kind=inner SuspiciousResponses on DeviceName, AccountName, RemoteIP
| where SuspiciousResponses.TimeGenerated between (SuspiciousRequests.TimeGenerated .. SuspiciousRequests.TimeGenerated + 30m)
| project TimeGenerated = SuspiciousRequests.TimeGenerated,
    DeviceName, AccountName, RemoteUrl, RemoteIP, InitiatingProcessFileName, ProcessCommandLine, TokenCount, RequestCount, TotalBytes
| order by TimeGenerated desc

```

--- 
<br>

## **References**
■ Hu, W., Huang, Y., Ji, Y., Li, C., & Rao, A. (2025) New Prompt Injection Attack Vectors Through MCP Sampling, Palo Alto Networks Unit 42, 6 December [Blog]. Available at: https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/ <br>
■ Raina, A. S. (2025) MCP Horror Stories: The WhatsApp Data Exfiltration Attack, Docker Blog, 13 November [Blog]. Available at: https://www.docker.com/blog/mcp-horror-stories-whatsapp-data-exfiltration-issue/

<br>

## **Author**
**Faiza Aslam**
