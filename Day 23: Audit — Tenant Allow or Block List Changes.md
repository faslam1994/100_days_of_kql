# Alert Title: Day 23: Audit — Tenant Allow or Block List Changes

<br>

## **Description**
This audit tracks administrative activity related to **Tenant Allow/Block List** changes in Microsoft 365.  
It surfaces operations invoked via `New-TenantAllowBlockListItems`, `Remove-TenantAllowBlockListItems`, and `Set-TenantAllowBlockListItems`, expands and normalizes parameter details (e.g., ListType, Entries, ExpirationDate, Block, Notes), and enriches with the associated **user session** from **SigninLogs** for accountability. This rule is intended for **change monitoring and governance**, and insider threat detection.<br>

<br>
Key indicators for detection: <br>
■ Who modified Allow/Block List entries <br>
■ What entities were added/removed/updated (domains, URLs, emails, etc.) <br>
■ Whether entries are blocking or allowing <br>
■ Expiration details and notes <br>
■ When the change happened (UTC) <br>
■ The M365 sign-in identity associated with the session <br>
<br>

<br>
<br>
<br>


## **Threats**
■ **Insider Threat**

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Initial Access <br>
■ Defence Evasion <br>
■ Impact <br>

<br>
  
     
<br>

### **Techniques**
■ **T1562 — Impair Defenses**: https://attack.mitre.org/techniques/T1562/ <br>
■ **T1190 — Exploit Public-Facing Application**: https://attack.mitre.org/techniques/T1190/ <br>
■ **T1078 – Boot or Service Initialization Scripts**: https://attack.mitre.org/techniques/T1078/  <br>

<br>

## **Severity**
**Low:** Visibility and accountability for configuration changes. <br>

<br>

## **Detection Type** 
■ Audit / Change Monitoring  <br>
■ Governance & Compliance Review  <br>

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft XDR Telemetry**: `CloudAppEvents` `SigninLogs`

<br>

## **False Positives**
■ Legitimate authorise TABL changes <br>

<br>

--- 


## **KQL Query**

```kusto

let lookback = ago(7d);
CloudAppEvents
| where TimeGenerated >= lookback
| where ObjectName has_any ("New-TenantAllowBlockListItems", "Remove-TenantAllowBlockListItems", "Set-TenantAllowBlockListItems")
// Parse the RawEventData JSON once
| extend RD = parse_json(RawEventData)
// Convenience fields from the JSON
| extend 
    CreationTimeUtc = todatetime(RD.CreationTime),
    Operation       = tostring(RD.Operation),
    AADSessionId    = tostring(RD.AppAccessContext.AADSessionId),
    ParamsArr       = RD.Parameters
// Expand Parameters array (Name/Value pairs) into rows
| mv-expand ParamsArr
| extend ParamName = tostring(ParamsArr.Name), ParamValue = tostring(ParamsArr.Value)
// Re-pivot Parameters back to columns per event
| summarize Params = make_bag(bag_pack(ParamName, ParamValue))
      by 
        TimestampUtc = coalesce(CreationTimeUtc, TimeGenerated),
        Operation, AADSessionId
// Extract the specific parameter fields you want
| extend
    Param_Type          = tostring(Params.ListType),
    Param_Entry         = tostring(Params.Entries),
    Param_Expiration    = todatetime(Params.ExpirationDate),
    Param_NoExpiration  = iff(tolower(tostring(Params.NoExpiration)) in ("true","1"), true,
                              iff(tolower(tostring(Params.NoExpiration)) in ("false","0"), false, bool(null))),
    Param_Block         = iff(tolower(tostring(Params.Block)) in ("true","1"), true,
                              iff(tolower(tostring(Params.Block)) in ("false","0"), false, bool(null))),
    Param_Notes         = tostring(Params.Notes)
// Shape output
| project 
    ["Timestamp [UTC]"] = TimestampUtc,
    Operation,
    ["Entity Type"] = Param_Type,
    ["Entity"] = Param_Entry,
    ExpirationDate = Param_Expiration,
    ["No Expiration"] = Param_NoExpiration,
    ["Block"] = Param_Block,
    ["Notes"] = Param_Notes,
    AADSessionId
| order by ["Timestamp [UTC]"] desc
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated >= lookback
    | summarize arg_max(TimeGenerated, *) by SessionId
    | project SessionId, UserPrincipalName
) on $left.AADSessionId == $right.SessionId
| project-away SessionId, AADSessionId
// -----------------------------
// INSERTED EXPIRY CALCULATION
// -----------------------------
| extend Expiry = case(
    ["No Expiration"] == true, "No Expiration Date",
    isnotnull(ExpirationDate), tostring(ExpirationDate),
    ""
)
// -----------------------------
| project ['Timestamp [UTC]'], UserPrincipalName, Operation, ['Entity Type'], Entity, Block, Expiry, Notes

 

```

--- 
<br>

## **References**
■ Microsoft (n.d.) Kusto Query Language learning resources [Online]. Available at: https://learn.microsoft.com/en-us/kusto/query/kql-learning-resources

<br>
<br>

## **Author**
**Faiza Aslam**
