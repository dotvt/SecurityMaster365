#  Bumblebee mail campaign

- **Description**
    - Cette requête permet de rechercher les mails qui pourraient être associés à une campagne Bumblebee
- **Références** 
    - https://www.bleepingcomputer.com/news/security/bumblebee-malware-attacks-are-back-after-4-month-break/
    - https://www.proofpoint.com/us/blog/threat-insight/bumblebee-buzzes-back-black
- **Techniques** 
    -  attack.collection
    -  attack.t1114.003
 - **Tables**
   - EmailEvents


### Defender Custom Detection Rules
```KQL
EmailEvents
| where Subject contains "Voicemail" or SenderFromAddress contains "quarlessa" 
| join kind = inner EmailAttachmentInfo on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress ,Subject, FileName, ReportId
```
