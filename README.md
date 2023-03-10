# Block Sentinel Entities on Azure WAF.

Detailed instructions on https://potsolutions.nl/2023/01/07/block-sentinel-entities-on-azure-waf/

For this to work you need:

-WAF policy (Frontdoor in this example).

-Anaytlic rule that creates incidents with IP Entities.

-Logic app that sends entities from the Sentinel incident to the function app API.

-BlockEntitiesWAF.cs code running on a function app in Azure, you can use Visual Studio Community to deploy it.

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
