# Modification des rôles RBAC Defender

- **Description**
    - Cette requête permet de lister les events correspondants au téléchargement du package d'offboarding.
- **Références** 
  - https://learn.microsoft.com/en-us/defender-xdr/m365d-permissions
  - https://learn.microsoft.com/en-us/defender-endpoint/rbac
  - https://kqlquery.com/posts/audit-defender-xdr/
      
- **MITRE ATT&CK Techniques** 

| Technique ID | Title    | Link    |
| ---  | --- | --- |

 - **Tables**
   - CloudAppEvents

## Defender XDR
```KQL
CloudAppEvents
| extend Workload = tostring(parse_json(RawEventData).Workload)
| where Workload contains "Defender"
| where ActionType endswith "Role"
| extend RoleName = tostring(parse_json(RawEventData).RoleName), RolePermissions = tostring(parse_json(RawEventData).RolePermissions), AssignedGroups = tostring(parse_json(RawEventData).AssignedGroups)
| project-reorder Timestamp, ActionType, AccountObjectId, RoleName, RolePermissions, AssignedGroups
```
