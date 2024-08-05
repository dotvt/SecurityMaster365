# Suppression de Custom Detection Rule

- **Description**
    - Cette requête permet de lister l'ensemble des CDR qui ont été supprimées dans Defender.
- **Références** 
  - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20XDR/CustomDetectionDeletion.md
  - https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview
  - https://kqlquery.com/posts/audit-defender-xdr/
- **MITRE ATT&CK Techniques** 

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1070 | Indicator Removal | https://attack.mitre.org/techniques/T1070/ |

 - **Tables**
   - CloudAppEvents

## Defender For Endpoint
```KQL
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "DeleteCustomDetection"
| extend RuleName = tostring(parse_json(RawEventData).RuleName), Query = tostring(parse_json(RawEventData).Query), AlertDescription = parse_json(RawEventData).AlertDescription
| project-reorder AccountDisplayName, AccountId, RuleName, AlertDescription, Query
```
