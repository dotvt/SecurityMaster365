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




## Defender Custom Detection Rules
```KQL
//Titre: Règles de forwarding/redirection externe
//description: Detects scenarios where an attacker creates a forwarding rules to a non company email in order to collect information.
//References:
//- https://redcanary.com/blog/email-forwarding-rules/
//- https://www.mandiant.com/sites/default/files/2021-11/wp-m-unc2452-000343.pdf
//- https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/
//- https://raw.githubusercontent.com/PwC-IR/Business-Email-Compromise-Guide/main/PwC-Business_Email_Compromise-Guide.pdf
//- https://docs.microsoft.com/en-us/microsoft-365/security/defender/alert-grading-playbook-email-forwarding?view=o365-worldwide
//Techniques:
//- attack.collection
//- attack.t1114.003
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
| where not( RawEventData.Parameters has_any (
        "@domain1.com", 
        "@domain2.com",
        "@domain3.com",
        "@domain3.com"))
| where RawEventData.Parameters contains "@"
| project Timestamp, ActionType, AccountDisplayName, RuleConfig = RawEventData.Parameters, RawEventData, ReportId, AccountId
| sort by Timestamp
```
