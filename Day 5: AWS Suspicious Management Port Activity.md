
# Alert Title: AWS Suspicious Management Port Activity

<br>

## **Description**
This alert surfaces inbound management‑port access to AWS resources, a behavior that mirrors Amazon’s discovery of a years‑long intrusion campaign linked to Russia’s GRU‑associated Sandworm group. 
The attackers did not exploit AWS itself but instead targeted misconfigured customer edge devices hosted on AWS, using exposed interfaces to gain initial access, harvest credentials, and move laterally across cloud‑connected infrastructure.
The KQL query examines repeated external connections, unique source IPs, and persistent activity to management ports, this query helps detect patterns similar to those observed in the GRU campaign, where attackers leveraged legitimate traffic flows to remain stealthy over multiple years.


<br>

## **Threats**
■ **SandWorm**  

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Persistence <br>
■ Exfiltration <br>
  

<br>

### **Techniques**
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/ <br>
■ **T1567.002 – Exfiltration to Cloud Storage**: https://attack.mitre.org/techniques/T1567/002/ <br>
■ **T1041 – Exfiltration Over C2 Channel**: https://attack.mitre.org/techniques/T1041/ <br>

<br>

## **Severity**
**High**: Detection examines misconfigured AWS‑hosted edge devices, enabling credential theft, persistence, and potential data exfiltration.

<br>

## **Detection Type** 
■ Behavioural Detection  <br>
■ TTP‑based  <br>

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **AWS**: `AWSVPCFlow`  

<br>

## **False Positives**
■ Legitimate administrative activity: Routine SSH/RDP or management traffic from corporate jump boxes or trusted third‑party vendors may appear suspicious if not included in allowlists. <br>
■ Automated security scanners: External compliance scans, penetration tests, or vulnerability assessment tools may generate repeated inbound hits on management ports. <br>
■ Misconfigured or orphaned cloud resources: Unused ENIs, stale public IP mappings, or incorrectly exposed management interfaces can generate noise that looks malicious but is operational misconfiguration rather than threat activity. <br>


<br>

--- 


## **KQL Query**

```kusto

//This query identifies inbound connections to AWS instances on management ports over the past 90 days, filtering out private and trusted CIDR ranges to reduce noise. It then aggregates the activity by Account, VPC, Region, and destination port, calculating metrics such as first/last seen, total hits, unique source IPs, total bytes (in bytes and MB), and produces sets of related attributes such as destination addresses, interface IDs, and TCP flags for deeper investigation.
// ===== PARAMETERS =====
let MgmtPorts = dynamic([22, 3389, 8080, 23]);
let TimeWindow = 90d;  // adjust as needed
let SetLimit = 1000;  // safeguard to cap array sizes

AWSVPCFlow
| where TimeGenerated > ago(TimeWindow)
| where FlowDirection == "ingress"
| where Action == "ACCEPT"
| where DstPort in (MgmtPorts)
| where not(ipv4_is_private(SrcAddr))
// Explicit CIDR exclusions, a watchlist can be included here to reduce noise:
| where not(
       ipv4_is_match(SrcAddr, "0.0.0.0/8")
)
// Summarize metrics and collect sets; group only by AccountId, VpcId, DstPort
| summarize
    // Core metrics
    FirstSeen            = min(TimeGenerated),
    LastSeen             = max(TimeGenerated),
    Hits                 = count(),
    DistinctPktSrcAddr   = dcount(PktSrcAddr),
    TotalBytes           = sum(Bytes),
    TotalMB              = sum(Bytes) / (1024 * 1024.0),

    // Sets for all other dimensions/fields
    InstanceIdSet        = make_set(InstanceId, SetLimit), //Can be blank as the flow goes through an ENI (Elastic Network Interface) that is not attached to an EC2 instance.
    InterfaceIdSet        = make_set(InterfaceId, SetLimit),
    DstAddrSet           = make_set(DstAddr, SetLimit),
    PktSrcAddrSet        = make_set(PktSrcAddr, SetLimit),
    PktDstAddrSet        = make_set(PktDstAddr, SetLimit),
    FlowDirectionSet     = make_set(FlowDirection, SetLimit),
    ActionSet            = make_set(Action, SetLimit),
    SrcAddrSet           = make_set(SrcAddr, SetLimit),
    TCPFlagSet           = make_set(TcpFlags, SetLimit),
    ProtocolSet          = make_set(Protocol, SetLimit)
  by
    AccountId, VpcId, DstPort, Region
| where Hits >= 20 and DistinctPktSrcAddr >= 1 and TotalBytes >= 10
| order by LastSeen desc

```

--- 
<br>

## **References**
■ Jacobs, S. (2025) *Amazon links long‑running AWS attacks to Russia’s GRU*, TechSpot, 20 December [Blog]. Available at: https://www.techspot.com/news/110671-amazon-links-long-running-aws-attacks-russia-gru.html <br>

<br>

## **Author**
**Faiza Aslam**
