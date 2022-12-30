using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Collections.Generic;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Linq;
using System.Text;

namespace BlockWAF
{
    public class http
    {
        public static string secret = "";
        public static string appid = "";
        public static string tenantid = "";
        public static string azureid = "";
        public static string resgrp = "";
        public static string wafpolicyname = "";

        public static string token { get; set; }
        public static string accessToken { get; set; }

        public static HttpClient httpclient { get; set; }

        public static async Task  GetToken()
        {
            ClientCredential credential = new ClientCredential(appid, secret);
            AuthenticationContext authContext = new AuthenticationContext($"https://login.microsoftonline.com/" + tenantid);
            AuthenticationResult authResult = await authContext.AcquireTokenAsync("https://management.azure.com/", credential);

            // Use the access token to authenticate to Azure resources
            accessToken = authResult.AccessToken;

        }
    }

    

    public static class BlockWAFIP
    {

        [FunctionName("BlockWAFIP")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");
            await http.GetToken();

            //get post
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var entities = JsonConvert.DeserializeObject<List<Entitie.Root>>(requestBody);

            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", http.accessToken);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            HttpResponseMessage response = await client.GetAsync("https://management.azure.com/subscriptions/" + http.azureid + "/resourceGroups/" + http.resgrp + "/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/" + http.wafpolicyname + "?api-version=2020-11-01");

            string result = await response.Content.ReadAsStringAsync();
            var currentwaf = JsonConvert.DeserializeObject<WAF.Root>(result);

            var newwaf = new WAF.Root();
            newwaf.location = currentwaf.location;
            newwaf.properties = new WAF.Properties();
            newwaf.properties.policySettings = currentwaf.properties.policySettings;
            newwaf.properties.managedRules = currentwaf.properties.managedRules;
            newwaf.properties.customRules = currentwaf.properties.customRules;
            newwaf.properties.policySettings = currentwaf.properties.policySettings;
            newwaf.sku = currentwaf.sku;


            var otherrules = currentwaf.properties.customRules.rules.Where(p => p.name != "BlockedIPs");
            var blockedIPs = currentwaf.properties.customRules.rules.FirstOrDefault(p => p.name == "BlockedIPs");

            var matchConditions = new List<WAF.MatchCondition>();
            var ips = new List<string>();

            foreach (var entity in entities)
            {
                if (entity.kind.Equals("Ip"))
                {
                    ips.Add(entity.properties.address);
                }
            }
            if (blockedIPs.matchConditions.FirstOrDefault().matchValue.SequenceEqual(ips))
            {
                return new OkObjectResult("ok");
            }
            blockedIPs.matchConditions.FirstOrDefault().matchValue = ips;


            var rules = (otherrules).ToList();
            rules.Add(blockedIPs);
            newwaf.properties.customRules.rules = rules;
            var post = JsonConvert.SerializeObject(newwaf, Formatting.None, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            });
            var poststring = post.ToString();
            var postresponse = await client.PutAsync("https://management.azure.com/subscriptions/" + http.azureid + "/resourceGroups/" + http.resgrp + "/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/" + http.wafpolicyname + "?api-version=2020-11-01", new StringContent(post, Encoding.UTF8, "application/json"));

            postresponse.EnsureSuccessStatusCode();

            return new OkObjectResult("ok");
        }
    }

    
}

namespace Entitie
{
    public class Properties
    {
        public string address { get; set; }
        public string friendlyName { get; set; }
    }

    public class Root
    {
        public string id { get; set; }
        public string type { get; set; }
        public string kind { get; set; }
        public Properties properties { get; set; }
    }
}

namespace WAF
{
    // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
    public class CustomRules
    {
        public List<Rule> rules { get; set; }
    }

    public class Exclusion
    {
        public string matchVariable { get; set; }
        public string selectorMatchOperator { get; set; }
        public string selector { get; set; }
    }

    public class ManagedRules
    {
        public List<ManagedRuleSet> managedRuleSets { get; set; }
    }

    public class ManagedRuleSet
    {
        public string ruleSetType { get; set; }
        public string ruleSetVersion { get; set; }
        public string ruleSetAction { get; set; }
        public List<RuleGroupOverride> ruleGroupOverrides { get; set; }
        public List<Exclusion> exclusions { get; set; }
    }

    public class MatchCondition
    {
        public string matchVariable { get; set; }
        public string selector { get; set; }
        public string @operator { get; set; }
        public bool negateCondition { get; set; }
        public List<string> matchValue { get; set; }
        public List<string> transforms { get; set; }
    }

    public class PolicySettings
    {
        public string enabledState { get; set; }
        public string mode { get; set; }
        public object redirectUrl { get; set; }
        public object customBlockResponseStatusCode { get; set; }
        public object customBlockResponseBody { get; set; }
        public string requestBodyCheck { get; set; }
    }

    public class Properties
    {
        public PolicySettings policySettings { get; set; }
        public CustomRules customRules { get; set; }
        public ManagedRules managedRules { get; set; }
        public List<object> frontendEndpointLinks { get; set; }
        public List<SecurityPolicyLink> securityPolicyLinks { get; set; }
        public List<object> routingRuleLinks { get; set; }
        public string resourceState { get; set; }
        public string provisioningState { get; set; }
    }

    public class Root
    {
        public string id { get; set; }
        public string type { get; set; }
        public string name { get; set; }
        public string location { get; set; }
        public Tags tags { get; set; }
        public Sku sku { get; set; }
        public Properties properties { get; set; }
    }

    public class Rule
    {
        public string name { get; set; }
        public string enabledState { get; set; }
        public int? priority { get; set; }
        public string ruleType { get; set; }
        public int? rateLimitDurationInMinutes { get; set; }
        public int? rateLimitThreshold { get; set; }
        public List<MatchCondition> matchConditions { get; set; }
        public string action { get; set; }
        public string ruleId { get; set; }
        public List<Exclusion> exclusions { get; set; }
    }

    public class RuleGroupOverride
    {
        public string ruleGroupName { get; set; }
        public List<Rule> rules { get; set; }
        public List<Exclusion> exclusions { get; set; }
    }

    public class SecurityPolicyLink
    {
        public string id { get; set; }
    }

    public class Sku
    {
        public string name { get; set; }
    }

    public class Tags
    {
    }


}
