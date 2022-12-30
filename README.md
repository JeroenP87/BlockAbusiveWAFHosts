# Block Abusive Hosts from Sentinel on Azure WAF.


Starting this off with a C# script that blocks IP addresses that were abusive in the last 24 hours on Azure Frontdoor. I wrote this as trying to accomplish it from a Logic App was a pain.

For this to work you need:

-WAF policy (Frontdoor in this example) that sends logs to Sentinel.

-Anaytlic rule that creates incidents with IP Entities.

-Logic app that sends entities from the Sentinel incident to the function app.

-C# code running on a function plan in Azure, you can use Visual Studio Community to deploy it.

-Application Registration with Access Rights on the WAF Policy.

-Custom WAF Deny rule with the name "BlockedIPs", match type IP address, variable RemoteAddr.

-Sentinel Analytic rule, run every 1 hour with data of the past 1 day.

query:


AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CDN"
    and Category == "FrontDoorWebApplicationFirewallLog"
    and ruleName_s !contains "Bots"
| where action_s == "Block"
| summarize RequestCount = count() by ClientIP = clientIP_s, UserAgent = userAgent_s, Resource
| where RequestCount > 1000
| order by RequestCount desc


You can test the functionality with PostMan by sending Post to: FunctionAppURI/api/BlockWAFIP

With body data:
[
  {
    "id": "",
    "type": "Microsoft.SecurityInsights/Entities",
    "kind": "Ip",
    "properties": {
      "address": "SOMEIP",
      "friendlyName": "SOMEIP"
    }
  },
  {
    "id": "",
    "type": "Microsoft.SecurityInsights/Entities",
    "kind": "Ip",
    "properties": {
      "address": "SOMEIP",
      "friendlyName": "SOMEIP"
    }
  }
]

-Buy me a coffee on www.buymeacoffee.com/potsolutions
