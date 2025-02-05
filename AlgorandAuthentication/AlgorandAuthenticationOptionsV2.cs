using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;

namespace AlgorandAuthenticationV2
{
    /// <summary>
    /// AVM data structure for algod server config
    /// </summary>
    public class AlgodConfig
    {
        public string Server { get; set; } = "";
        public string Token { get; set; } = "";
        public string Header { get; set; } = "";
        public ulong MsPerBlock { get; set; } = 2800;
    }/// <summary>
    /// List of network structures
    /// </summary>
    public class AllowedNetworks : Dictionary<string, AlgodConfig>
    {

    }
    /// <summary>
    /// AlgorandAuthenticationOptionsV2 is object with posibility of multiple networks to be accepted for authentication
    /// </summary>
    public class AlgorandAuthenticationOptionsV2 : AuthenticationSchemeOptions
    {
        public bool CheckExpiration { get; set; } = false;
        public string Realm { get; set; } = "Authentication";
        public bool EmptySuccessOnFailure { get; set; } = false;
        public bool Debug { get; set; } = false;
        public AllowedNetworks AllowedNetworks { get; set; } = new AllowedNetworks()
        {
            ["wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="] = new AlgodConfig()
            {
                Server = "https://mainnet-api.4160.nodely.dev"
            }
        };
    }
}
