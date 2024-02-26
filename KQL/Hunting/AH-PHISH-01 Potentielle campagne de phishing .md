# Potentielle campagne de phishing

- **Description**
    - Cette requête permet d'identifier les potentielles campagnes de phishing envoyées par un domaine peu fréquent.
- **Techniques** 
    - T1566
 - **Tables**
   - EmailEvents
  
### Defender XDR : Advanced Hunting Query 
```KQL
// Remplacer {Trigger} par le nombre de mail envoyé
let RareDomainThreshold = {Trigger};
let TotalSenderThreshold = 1;
let RareDomains = EmailEvents
| summarize TotalDomainMails = count() by SenderFromDomain
| where TotalDomainMails <= RareDomainThreshold
| project SenderFromDomain;
EmailEvents
| where EmailDirection == "Inbound"
| where SenderFromDomain in (RareDomains)
| where isnotempty(EmailClusterId)
| join kind=inner EmailUrlInfo on NetworkMessageId
| summarize Subjects = make_set(Subject), Senders = make_set(SenderFromAddress) by EmailClusterId
| extend TotalSenders = array_length(Senders)
| where TotalSenders >= TotalSenderThreshold
```
