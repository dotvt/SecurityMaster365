# Activité d'un utilisateur sur ses inbox rules

- **Description**
    - Cette requête permet de trouver l'ensemble des inbox rules crées sur une boîte mail.
- **Techniques** 
    -  Email collection T1114
 - **Tables**
   - CloudAppEvents
     
> [!NOTE]
> Il est fortement recommandé de bloquer le forwarding automatisé dans les stratégies **anti-spam outbound** Microsoft Defender for Office.

### Defender Advanced Hunting Query 
```KQL
let action_types = pack_array(
    "New-InboxRule",
    "UpdateInboxRules",
    "Set-InboxRule",
    "Set-Mailbox",
    "New-TransportRule",
    "Set-TransportRule");
CloudAppEvents
//Remplacer {User} par NOM Prénom 
| where AccountDisplayName contains {User}
| where ActionType in (action_types)
| project Timestamp, ActionType, AccountDisplayName, RuleConfig = RawEventData
```
