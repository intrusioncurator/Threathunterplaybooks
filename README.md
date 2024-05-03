KQL URL Protection Report🌍

For organization subscribed to Defender for Office 365, M365 or security admin would most of time go to DefenderXDR portal "Reports" > "Email & Collaboration" > "URL protection report" to check if a particular user has click on a malicious link and if it was blocked by Office 365 ATP.

Do you know you can access all these Threat Intelligence URL Click Data in CloudAppEvents table? 😎

Using DefenderXDR Advanced Hunting and the below KQL will provide information similar to the "URL Protection Report", you can further summarize these set of data to allow you to better understand the threats currently faced by your suite of Office 365 applications that support SafeLinks and possibly tweak your SafeLinks configuration to improve your organization Office 365 application protection.🛡️

1.	CloudAppEvents
2.	| where ActionType == "TIUrlClickData"
3.	| where RawEventData.Workload=="ThreatIntelligence"
4.	| extend AppName = RawEventData.AppName
5.	| extend AccountUpn = RawEventData.UserId
6.	| extend UserIP = RawEventData.UserIp
7.	| extend ClickURL = RawEventData.Url
8.	| extend UrlClickAction = RawEventData.UrlClickAction
9.	| extend TimeOfClick = RawEventData.TimeOfClick
10.	| where ActivityType=="Basic"
11.	| project AppName, AccountUpn, UserIP, ClickURL, UrlClickAction, TimeOfClick
12.	| where UrlClickAction == 2 //User blocked from navigating to the URL
 

UrlClickAction Value Representation:
https://lnkd.in/ds_E7Kyg
