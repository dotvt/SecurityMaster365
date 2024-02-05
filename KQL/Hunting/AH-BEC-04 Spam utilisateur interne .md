# Inbox rules vers une adresse particulière

- **Description**
    - Cette requête permet d'identifier un utilisateur potentiellement compromis en analysant le nombre de mails sortant / intra-organisationnel envoyés.  
- **Techniques** 
    - T1566
 - **Tables**
   - EmailEvents
  
> [!NOTE]
> Il est fortement recommandé d'activer une limite d'envois dans les stratégies **anti-spam outbound** Microsoft Defender for Office


### Defender Advanced Hunting Query 
```KQL
EmailEvents
// Remplacer {date} par le temps recherché sous le format YYYY-MM-DD ou YYYY-MM-DD HH:MM pour une meilleure précision
| where Timestamp between (<start> .. <end>) 
| where EmailDirection in ("Outbound","Intra-org")
| project RecipientEmailAddress, SenderFromAddress, SenderMailFromAddress, SenderObjectId, NetworkMessageId 
| summarize RecipientCount = dcount(RecipientEmailAddress), UniqueEmailSentCount = dcount(NetworkMessageId) by SenderFromAddress, SenderMailFromAddress, SenderObjectId
| sort by UniqueEmailSentCount desc 
```
