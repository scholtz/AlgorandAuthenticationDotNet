using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;

namespace AlgorandAuthenticationV2
{
    /// <summary>
    /// AVM data structure for algod server config
    /// </summary>
    public class AlgodConfig
    {
        /// <summary>
        /// Gets or sets the server URL for the algod configuration.
        /// </summary>
        public string Server { get; set; } = "";

        /// <summary>
        /// Gets or sets the token for authentication with the algod server.
        /// </summary>
        public string Token { get; set; } = "";

        /// <summary>
        /// Gets or sets the header for requests to the algod server.
        /// </summary>
        public string Header { get; set; } = "";

        /// <summary>
        /// Gets or sets the milliseconds per block for the network.
        /// </summary>
        public ulong MsPerBlock { get; set; } = 2800;
    }

    /// <summary>
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
        /// <summary>
        /// Gets or sets a value indicating whether to check the expiration of the authentication.
        /// When false (the default), a captured/leaked "SigTx" header can be replayed indefinitely because no
        /// expiration is enforced. Production deployments should set this to true.
        /// </summary>
        public bool CheckExpiration { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether to allow empty accounts.
        /// </summary>
        public bool AllowEmptyAccounts { get; set; } = false;

        /**
         * Default realm used for authentication challenge
         * 
         *@deprecated Use Realms list instead
         */
        public string Realm { get; set; } = "Authentication";

        /// <summary>
        /// Gets or sets the list of realms for authentication challenges.
        /// </summary>
        public List<string> Realms { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets a value indicating whether to return an empty success on failure.
        /// When true, a signature/verification failure results in a *successful* authentication with an empty
        /// identity instead of a rejected request. Any consumer enabling this must check for the
        /// "AlgoAuthFallback" claim (or a non-empty NameIdentifier) before treating the caller as authorized -
        /// checking only User.Identity.IsAuthenticated is not sufficient and will treat unauthenticated callers
        /// as logged in.
        /// </summary>
        public bool EmptySuccessOnFailure { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether debug mode is enabled.
        /// Must never be enabled in production. When true, a prefix/length of the Authorization header (a
        /// replayable signed transaction) is written to the configured logger.
        /// </summary>
        public bool Debug { get; set; } = false;

        /// <summary>
        /// Gets or sets the allowed networks for authentication.
        /// </summary>
        public AllowedNetworks AllowedNetworks { get; set; } = new AllowedNetworks()
        {
            ["wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="] = new AlgodConfig()
            {
                Server = "https://mainnet-api.4160.nodely.dev"
            }
        };
    }
}
