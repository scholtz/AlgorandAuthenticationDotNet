using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;

namespace AlgorandAuthentication
{
    public class AlgorandAuthenticationOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// When false (the default), a captured/leaked "SigTx" header can be replayed indefinitely because no
        /// expiration is enforced. Production deployments should set this to true.
        /// </summary>
        public bool CheckExpiration { get; set; } = false;
        public string AlgodServer { get; set; } = "";
        public string AlgodServerToken { get; set; } = "";
        public string AlgodServerHeader { get; set; } = "";
        public string Realm { get; set; } = "Authentication";
        public string NetworkGenesisHash { get; set; }
        public ulong MsPerBlock { get; set; } = 4500;
        /// <summary>
        /// When true, a signature/verification failure results in a *successful* authentication with an empty
        /// identity instead of a rejected request. Any consumer enabling this must check for the
        /// "AlgoAuthFallback" claim (or a non-empty NameIdentifier) before treating the caller as authorized -
        /// checking only User.Identity.IsAuthenticated is not sufficient and will treat unauthenticated callers
        /// as logged in.
        /// </summary>
        public bool EmptySuccessOnFailure { get; set; } = false;
        /// <summary>
        /// Must never be enabled in production. When true, the raw Authorization header (a replayable signed
        /// transaction) is written to the configured logger.
        /// </summary>
        public bool Debug { get; set; } = false;
    }
}
