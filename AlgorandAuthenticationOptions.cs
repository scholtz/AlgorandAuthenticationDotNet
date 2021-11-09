using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AlgorandAuthentication
{
    public class AlgorandAuthenticationOptions : AuthenticationSchemeOptions
    {
        public bool CheckExpiration { get; set; } = false;
        public string AlgodServer { get; set; } = "";
        public string AlgodServerToken { get; set; } = "";
        public string Realm { get; set; } = "Authentication";
        public string NetworkGenesisHash { get; set; }
    }
}
