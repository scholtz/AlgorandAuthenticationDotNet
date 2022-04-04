using Algorand;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using ISystemClock = Microsoft.AspNetCore.Authentication.ISystemClock;

namespace AlgorandAuthentication
{
    /// <summary>
    /// This class handles AlgorandAuthentication and allows services to communicate between each other in the simplest possible secure way.
    /// </summary>
    public class AlgorandAuthenticationHandler : AuthenticationHandler<AlgorandAuthenticationOptions>, IAuthenticationRequestHandler, IAuthenticationHandler
    {
        public const string ID = "AlgorandAuthentication";
        public const string AuthPrefix = "SigTx ";
        private readonly ILogger<AlgorandAuthenticationHandler> logger;
        private static DateTimeOffset? t;
        private static ulong block;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        /// <param name="encoder"></param>
        public AlgorandAuthenticationHandler(
            IOptionsMonitor<AlgorandAuthenticationOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, loggerFactory, encoder, clock)
        {
            this.logger = loggerFactory.CreateLogger<AlgorandAuthenticationHandler>();
        }
        /// <summary>
        /// Handle Request
        /// </summary>
        /// <returns></returns>
        public async Task<bool> HandleRequestAsync()
        {
            logger.LogInformation("HandleRequestAsync");
            return false;
        }

        /// <summary>
        /// Add this code to end of configure:
        /// services
        ///     .AddAuthentication(AlgorandAuthenticationHandler.ID)
        ///     .AddAlgorand(AlgorandAuthenticationHandler.ID, o =>
        ///     {
        ///         o.CheckExpiration = false;
        ///         o.AlgodServer = "";
        ///         o.AlgodServerToken = "";
        ///         o.Realm = "Authentication";
        ///     });
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                logger.LogInformation("HandleAuthenticateAsync");
                if (!Request.Headers.ContainsKey("Authorization"))
                    return AuthenticateResult.NoResult();

                var auth = Request.Headers["Authorization"].ToString();
                if (!auth.StartsWith(AuthPrefix))
                {
                    return AuthenticateResult.NoResult();
                }
                var tx = Convert.FromBase64String(auth.Replace(AuthPrefix, ""));
                var tr = Algorand.Encoder.DecodeFromMsgPack<SignedTransaction>(tx);

                if (!Verify(tr.tx.sender.Bytes, tr.tx.BytesToSign(), tr.sig.Bytes))
                {
                    return AuthenticateResult.Fail(new Exception("Signature is invalid"));
                }
                if (Convert.ToBase64String(tr.tx.genesisHash.Bytes) != Options.NetworkGenesisHash)
                {
                    return AuthenticateResult.Fail(new Exception("Invalid Network"));
                }
                if (!string.IsNullOrEmpty(Options.Realm))
                {
                    var realm = Encoding.ASCII.GetString(tr.tx.note);
                    if (Options.Realm != realm)
                    {
                        // todo: add meaningful message
                        logger.LogTrace($"Wrong realm. Expected {Options.Realm} received {realm}");
                        return AuthenticateResult.Fail(new Exception("Wrong Realm"));
                    }
                }
                DateTimeOffset? expiration = null;
                if (Options.CheckExpiration)
                {
                    ulong estimatedCurrentBlock;
                    if (t.HasValue && t.Value.AddHours(1) > DateTimeOffset.UtcNow)
                    {
                        estimatedCurrentBlock = Convert.ToUInt64((DateTimeOffset.UtcNow - t.Value).TotalSeconds) / 5 + block;
                    }
                    else
                    {
                        var client = new Algorand.V2.AlgodApi(Options.AlgodServer, Options.AlgodServerToken);

                        var c = await client.GetStatusAsync();
                        if (c.LastRound.HasValue)
                        {
                            t = DateTimeOffset.UtcNow;
                            block = (ulong)c.LastRound.Value;
                        }
                        estimatedCurrentBlock = block;
                    }

                    if (tr.tx.lastValid.Value < estimatedCurrentBlock)
                    {
                        return AuthenticateResult.Fail(new Exception("Session timed out"));
                    }
                    expiration = DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds((tr.tx.lastValid.Value - estimatedCurrentBlock) * Options.MsPerBlock);
                }

                var user = tr.tx.sender.ToString();
                var claims = new List<Claim>() {
                    new Claim(ClaimTypes.NameIdentifier,user),
                    new Claim(ClaimTypes.Name,user),
                };

                if (Options.CheckExpiration)
                {
                    if (expiration.HasValue)
                    {
                        claims.Add(new Claim("exp", expiration.Value.ToUnixTimeSeconds().ToString()));
                    }
                    claims.Add(new Claim("AlgoValidFrom", tr.tx.firstValid.Value.ToString()));
                    claims.Add(new Claim("AlgoValidUntil", tr.tx.lastValid.Value.ToString()));
                }

                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }
            catch (Exception e)
            {
                return AuthenticateResult.Fail(e);
            }
        }

        private bool Verify(byte[] address, byte[] message, byte[] sig)
        {

            var signer = new Ed25519Signer();
            var pk = new Ed25519PublicKeyParameters(address, 0);
            signer.Init(false, pk);
            signer.BlockUpdate(message.ToArray(), 0, message.ToArray().Length);
            return signer.VerifySignature(sig);
        }
    }
}