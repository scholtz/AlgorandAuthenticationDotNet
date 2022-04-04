using Microsoft.AspNetCore.Authentication;

namespace AlgorandAuthentication
{
    public class AlgorandAuthenticationOptions : AuthenticationSchemeOptions
    {
        public bool CheckExpiration { get; set; } = false;
        public string AlgodServer { get; set; } = "";
        public string AlgodServerToken { get; set; } = "";
        public string Realm { get; set; } = "Authentication";
        public string NetworkGenesisHash { get; set; }
        public ulong MsPerBlock { get; set; } = 4500;
    }
}
