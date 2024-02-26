# Clic autorisé sur une URL

- **Description**
    - Cette requête permet de rechercher l'ensemble des clics autorisés sur une URL reçue dans un mail
 
> [!WARNING]
> le tracking des clics doit être autorisés dans les stratégies **SafeLink**

- **Techniques** 
    -  attack.collection
    -  attack.t1114.003
 - **Tables**
   - UrlClickEvents
   - EmailEvents


### Defender XDR : Advanced Hunting Query 
```KQL
UrlClickEvents
// Remplacer {date} par le temps recherché sous le format YYYY-MM-DD ou YYYY-MM-DD HH:MM pour une meilleure précision
| where Timestamp between (datetime({date}) .. datetime({date})) 
//remplacer {mail} par l'adresse de l'utilisateur concerné
| where AccountUpn contains "{mail}" 
// remplacer {Url} par l'Url
| where Url contains "{Url}" 
| where ActionType has "ClickAllowed" or IsClickedThrough !="0"
| join kind = inner EmailEvents on NetworkMessageId
// Remplacer {sender} avec l'adresse de l'expéditeur
| where SenderFromAddress contains "{sender}"
| project Timestamp, AccountUpn, SenderFromDomain, Url,ActionType, Subject, NetworkMessageId
| sort by Timestamp
```
