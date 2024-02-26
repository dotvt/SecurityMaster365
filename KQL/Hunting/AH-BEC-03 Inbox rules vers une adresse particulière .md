# Inbox rules vers une adresse particulière

- **Description**
    - Cette requête permet de trouver l'ensemble des inbox rules redirigeant des message vers une adresse / domaine particulier. (requête inverse de [AH-BEC-02 Activité d'un utilisateur sur ses inbox rules](https://github.com/dotvt/SecurityMaster365/blob/4d560d032f56e2e9c5796b1acc7dccefd8e8e60d/KQL/Hunting/AH-BEC-02%20Activit%C3%A9%20d'un%20utilisateur%20sur%20ses%20inbox%20rules.md)
- **Techniques** 
    -  Email collection T1114
 - **Tables**
   - CloudAppEvents
  
> [!NOTE]
> Il est fortement recommandé de bloquer le forwarding automatisé dans les stratégies **anti-spam outbound** Microsoft Defender for Office.

### Defender XDR : Advanced Hunting Query 
```KQL
CloudAppEvents
| where ActionType in (
        "Set-Mailbox", 
        "New-InboxRule", 
        "Set-InboxRule", 
        "New-TransportRule", 
        "Set-TransportRule") 
| project Timestamp, ActionType, AccountDisplayName, RuleConfig = RawEventData.Parameters, RawEventData
// Remplacer {RECIPIENT} par l'adresse ou le domaine du destinataire
| where RuleConfig has "{RECIPIENT}"
```
