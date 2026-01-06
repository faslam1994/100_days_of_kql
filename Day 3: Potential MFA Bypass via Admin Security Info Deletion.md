
# Alert Title: Potential MFA Bypass via Admin Security Info Deletion

<br>

## **Description**
Adversary with administrative access had deliberately removed a user’s MFA security information, temporarily weakening the account’s authentication protections. This allowed the attacker to sign in or perform actions with reduced or no MFA challenges during the exposure window. 
Within 24 hours, the MFA configuration was restored to evade detection and blend in with legitimate administrative activity. 
During this period, anomalous sign-ins from multiple IP addresses, devices, operating systems, or browsers may be observed, indicating potential account misuse. This pattern is consistent with the Mark and Spencer–style identity attack, involving MFA bypass, privilege abuse, and possible insider or compromised admin activity.

<br>

## **Threats**
■ **Scatter Spider**  

<br>

## **MITRE ATT&CK Techniques**

### **Tactics**
■ Credential Access <br>
■ Persistence <br>
■ Initial Access <br>
■ Defense Evasion <br>
■ Privilege Escalation <br>

<br>

### **Techniques**
■ **T1556 – Modify Authentication Process**: https://attack.mitre.org/techniques/T1556/ <br>
■ **T1098 – Account Manipulation**: https://attack.mitre.org/techniques/T1098/ <br>
■ **T1078 – Valid Accounts**: https://attack.mitre.org/techniques/T1078/ <br>

<br>


## **Severity**
**High**: Administrative tampering with MFA security information leading to potential account takeover and lateral movement.

<br>

## **Detection Type**
■ Threat Hunting  
■ Behavioural Detection  
■ TTP‑based  

<br>

## **Data Sources**
### **Microsoft Sentinel**
■ **Microsoft Entra**: `SignInLogs`  

<br>

## **False Positives**
■  User loses phone or replaces device leading to an Admin removing old MFA methods and re-enrolls MFA. <br>
■  Helpdesk temporarily removes MFA to resolve user lockout or device issues. <br>
■  Security or IAM teams testing MFA workflows.<br>

<br>

--- 


## **KQL Query**

```kusto

let mfaevent = AuditLogs
    | where OperationName contains "Admin deleted security info"
    // Initiator Parsed
    | extend InitiatorParsed = parse_json(InitiatedBy)
    | extend 
        InitiatorDisplayName = tostring(InitiatorParsed.user.displayName),
        InitiatorIPAddress = tostring(InitiatorParsed.user.ipAddress)
    // Target Resource Parsed
    | extend TargetResourcesParsed = parse_json(TargetResources)
    | mv-expand TargetResourcesParsed
    | extend 
        TargetUserPrincipalName = tostring(TargetResourcesParsed.userPrincipalName),
        TargetDisplayName = tostring(TargetResourcesParsed.displayName),
        TargetType = tostring(TargetResourcesParsed.type),
        DeletedSecurityInfo_Time = todatetime(TimeGenerated)
    | project
        TargetUserPrincipalName,
        TargetDisplayName,
        InitiatorDisplayName,
        InitiatorIPAddress,
        TargetType,
        DeletedSecurityInfo_Time
    | join kind=innerunique (
        AuditLogs
        | where OperationName contains "Restore multifactor authentication on all remembered devices"
        | extend TargetResourcesParsed = parse_json(TargetResources)
        | mv-expand TargetResourcesParsed
        | extend 
            TargetUserPrincipalName = tostring(TargetResourcesParsed.userPrincipalName),
            RestoreMFA_Time = todatetime(TimeGenerated)
        | project TargetUserPrincipalName, RestoreMFA_Time
    ) on $left.TargetUserPrincipalName == $right.TargetUserPrincipalName
    // Use datetime_diff to filter pairs within 24 hours
| extend TimeDiffHours = abs(datetime_diff('hour', RestoreMFA_Time, DeletedSecurityInfo_Time))
| where TimeDiffHours <= 24
    | project
        TargetUserPrincipalName,
        TargetDisplayName,
        TargetType,
        InitiatorDisplayName,
        InitiatorIPAddress,
        DeletedSecurityInfo_Time,
        RestoreMFA_Time
    | sort by DeletedSecurityInfo_Time desc
;
mfaevent
| join kind=inner (
    SigninLogs
    | extend DeviceDetailParsed = parse_json(DeviceDetail)
    | extend 
        DeviceOS = tostring(DeviceDetailParsed.operatingSystem),
        DeviceBrowser = tostring(DeviceDetailParsed.browser),
        DeviceName = tostring(DeviceDetailParsed.displayName),
        DomainJoined = tostring(DeviceDetailParsed.trustType),
        SigninIPAddress = IPAddress,
        SigninTime = todatetime(TimeGenerated),
        SigninStatus = iff(ResultType == 0, "Success", "Failure")
    | project
        TargetUserPrincipalName = UserPrincipalName,
        SigninIPAddress,
        DeviceOS,
        DeviceBrowser,
        DeviceName,
        DomainJoined,
        SigninTime,
        SigninStatus,
        AppDisplayName
) on $left.TargetUserPrincipalName == $right.TargetUserPrincipalName
| summarize 
    SigninIPWithTimes = make_set(strcat(SigninIPAddress, " @ ", format_datetime(SigninTime, 'yyyy-MM-dd HH:mm:ss'), " [", SigninStatus, "]")),
    DeviceOS = make_set(DeviceOS), 
    DeviceBrowsers = make_set(DeviceBrowser),
    DeviceNames = make_set(DeviceName),
    DomainJoinedStatus = make_set(DomainJoined),
    AppSignIn = make_set(AppDisplayName),
    DistinctIPCount = dcount(SigninIPAddress),
    DistinctDeviceOSCount = dcount(DeviceOS),
    DistinctBrowserCount = dcount(DeviceBrowser),
    DistinctDeviceNames = dcount(DeviceName)
    by
    TargetUserPrincipalName,
    TargetDisplayName,
    TargetType,
    InitiatorDisplayName,
    InitiatorIPAddress,
    DeletedSecurityInfo_Time,
    RestoreMFA_Time
| extend 
    IPChangeDetected = iff(DistinctIPCount > 1, "Yes", "No"),
    MultipleDevicesOS = iff(DistinctDeviceOSCount > 1, "Yes", "No"),
    MultipleDevices = iff(DistinctDeviceNames > 1, "Yes", "No"),
    MultipleBrowsers = iff(DistinctBrowserCount > 1, "Yes", "No")
| sort by DeletedSecurityInfo_Time desc
```

--- 
<br>

## **References**
■  Abrams, L. (2025) Marks & Spencer breach linked to Scattered Spider ransomware attack, BleepingComputer, 28 April [Online]. Available at: https://www.bleepingcomputer.com/news/security/marks-and-spencer-breach-linked-to-scattered-spider-ransomware-attack/ <br>
■  Davey, J. and Sandle, P. (2025) Britain’s M&S says cyberattack will cost about $400 million, Reuters, 21 May [Online]. Available at: https://www.reuters.com/business/media-telecom/britains-ms-says-cyberattack-cost-400-million-2025-05-21 <br>

<br>

## **Author**
**Faiza Aslam**
