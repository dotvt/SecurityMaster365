# Inbox rules : forwarding externe

- **Description**
    - Cette requête permet de rechercher l'ensemble des règles créés sur une boîte mail redirigeant des e-mails chez un domaine n'appartenant pas à l'organisation.
- **Références** 
    - https://redcanary.com/blog/email-forwarding-rules/
    - https://www.mandiant.com/sites/default/files/2021-11/wp-m-unc2452-000343.pdf
    - https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/
    - https://raw.githubusercontent.com/PwC-IR/Business-Email-Compromise-Guide/main/PwC-Business_Email_Compromise-Guide.pdf
- **Techniques** 
    -  attack.collection
    -  attack.t1114.003
 - **Tables**
   - CloudAppEvents


## Defender Custom Detection Rules
```KQL
CloudAppEvents
| where ActionType in (
        "Set-Mailbox", 
        "New-InboxRule", 
        "Set-InboxRule", 
        "New-TransportRule", 
        "Set-TransportRule") 
| where RawEventData.Parameters has_any (
        "ForwardingSmtpAddress", 
        "RedirectTo", 
        "ForwardAsAttachmentTo", 
        "ForwardTo",
        "ForwardingAddress",
        "RedirectMessageTo")
// Remplacer {Domain} par les domaines de l'organisation.
| where not( RawEventData.Parameters has_any (
        "{Domain}", 
        "{Domain}",
        "{Domain}",
        "{Domain}"))
| where RawEventData.Parameters contains "@"
| project Timestamp, ActionType, AccountDisplayName, RuleConfig = RawEventData.Parameters, RawEventData, ReportId, AccountId
| sort by Timestamp
```
