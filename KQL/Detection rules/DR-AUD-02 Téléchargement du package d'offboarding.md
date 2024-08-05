# Defender For Endpoint Offboarding Package Downloaded

- **Description**
    - Cette requête permet de lister les events correspondants au téléchargement du package d'offboarding.
- **Références** 
    - https://learn.microsoft.com/en-us/defender-endpoint/offboard-machines
    - https://kqlquery.com/posts/audit-defender-xdr/
      
- **MITRE ATT&CK Techniques** 

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |

 - **Tables**
   - CloudAppEvents

## Defender For Endpoint
```KQL
CloudAppEvents
| where ActionType == "DownloadOffboardingPkg"
| extend UserId = tostring(parse_json(RawEventData).UserId), ClientIP = tostring(parse_json(RawEventData).ClientIP)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder Timestamp, InitiatedByAccountName, UserId, ClientIP, ActionType
```
