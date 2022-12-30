# SentinelAutomation

Block Abusive Hosts from Sentinel on Azure WAF.

Starting this off with a C# script that blocks IP addresses that were abusive in the last 24 hours on Azure Frontdoor. I wrote this as running it from a Logic App was unreliable.

For this to work you need:

-WAF policy (Frontdoor in this example) that sends logs to Sentinel
-Anaytlic rule that creates incidents with IP Entities
-Logic app that sends entities from the Sentinel incident to the function app
-C# code running on a function consumption plan
-Custom WAF Deny rule with the name "BlockedIPs", match type IP address, variable RemoteAddr
-Buy a coffee on buymeacoffee.com/potsolutions

Sentinel Analytic rule:
-run every 1 hour with data of the past 1 day

query:

// [Azure Front Door Standard/Premium] Top 20 blocked clients by IP and rule 
// Show top 20 blocked clients by IP and rule name. 
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CDN"
    and Category == "FrontDoorWebApplicationFirewallLog"
    and ruleName_s !contains "Bots"
| where action_s == "Block"
| summarize RequestCount = count() by ClientIP = clientIP_s, UserAgent = userAgent_s, Resource
| where RequestCount > 1000
| order by RequestCount desc


https://www.buymeacoffee.com/potsolutions
