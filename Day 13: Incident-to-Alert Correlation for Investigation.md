
# Alert Title: Incident-to-Alert Correlation for Investigation
<br>

## **Description**
This query correlates Microsoft Sentinel Security Incidents with their associated Security Alerts to provide a consolidated view of alert activity within an incident. <br>
It expands alert IDs from incidents, joins them with alert details, and summarizes key metrics such as alert count, severity distribution, and impacted entities. <br>
<br>
**This detection helps analysts quickly:** <br>
■  Identify all alerts tied to a specific incident <br>
■  Understand the timeline and severity of related alerts <br>
■  Prioritize investigation based on alert aggregation <br>

<br>
<br>

## **Threats**
■ **Not a direct threat detection query**
■ **Used for incident enrichment and triage**

<br>
<br>

## **MITRE ATT&CK Techniques**
■  N/A – This query does not map to ATT&CK techniques directly; it supports investigation workflows.
<br>
<br>

## **Severity**
**Informational**: This query does not detect malicious activity but provides contextual correlation for active incidents.
<br>
<br>

## **Detection Type** 
■ Incident Investigation <br>
■ Alert Correlation <br>
■ SOC Workflow Enhancement <br>

<br>
<br>

## **Data Sources**
### **Microsoft Sentinel**
■ `SecurityIncident`
■ `SecurityAlert`

<br>

## **False Positives**
■ Not Applicable.

<br>

--- 

## **KQL Query 1**

```kusto
let IncidentAlerts = SecurityIncident
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| project AlertId, IncidentNumber, Title, IncidentUrl;

SecurityAlert
|where AlertName contains "Add Alert Name Here " 
| extend SystemAlertId = tostring(SystemAlertId)
| join kind=inner (IncidentAlerts) on $left.SystemAlertId == $right.AlertId
| project IncidentNumber, AlertName, AlertSeverity, TimeGenerated, CompromisedEntity, Title, AlertLink
| summarize 
    StartTime = min(TimeGenerated), 
    EndTime = max(TimeGenerated), 
    AlertCount = count(), 
    Entities = make_set(CompromisedEntity),
    IncidentNumbers = make_set(IncidentNumber),
    Severities = make_set(AlertSeverity),
    AlertLink = make_set(AlertLink)
    by AlertName, Title
| order by EndTime desc


```

--- 
<br>
<br>

## **KQL Query 2**

```kusto
let IncidentAlerts = SecurityIncident
|where Title contains "Add Title Here " 
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| project AlertId, IncidentNumber, Title, IncidentUrl;

SecurityAlert
| extend SystemAlertId = tostring(SystemAlertId)
| join kind=inner (IncidentAlerts) on $left.SystemAlertId == $right.AlertId
| project IncidentNumber, AlertName, AlertSeverity, TimeGenerated, CompromisedEntity, Title, AlertLink
| summarize 
    StartTime = min(TimeGenerated), 
    EndTime = max(TimeGenerated), 
    AlertCount = count(), 
    Entities = make_set(CompromisedEntity),
    IncidentNumbers = make_set(IncidentNumber),
    Severities = make_set(AlertSeverity),
    AlertLink = make_set(AlertLink)
    by AlertName, Title
| order by EndTime desc



```

--- 

<br>

## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources?view=microsoft-fabric <br>

<br>

## **Author**
**Faiza Aslam**
