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
            if (Options.Debug)
            {
                logger.LogInformation("HandleRequestAsync");
                await Task.Delay(1);
            }
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
                if (!Request.Headers.ContainsKey("Authorization"))
                    throw new UnauthorizedException("No authorization header");
                if (Options.Debug)
                {
                    logger.LogDebug($"Auth header: {Request.Headers["Authorization"].ToString()}");
                }
                var auth = Request.Headers["Authorization"].ToString();
                if (!auth.StartsWith(AuthPrefix))
                {
                    throw new UnauthorizedException($"Authorization header does not start with prefix {AuthPrefix}");
                }
                var tx = Convert.FromBase64String(auth.Replace(AuthPrefix, ""));
                var tr = Algorand.Utils.Encoder.DecodeFromMsgPack<Algorand.Algod.Model.Transactions.SignedTransaction>(tx);

                if (!Verify(tr.Tx.Sender.Bytes, tr.Tx.BytesToSign(), tr.Sig.Bytes))
                {
                    throw new UnauthorizedException("Signature is invalid");
                }
                if (Convert.ToBase64String(tr.Tx.GenesisHash.Bytes) != Options.NetworkGenesisHash)
                {
                    throw new UnauthorizedException("Invalid Network");
                }
                if (!string.IsNullOrEmpty(Options.Realm))
                {
                    var realm = Encoding.ASCII.GetString(tr.Tx.Note);
                    if (Options.Realm != realm)
                    {
                        // todo: add meaningful message
                        throw new UnauthorizedException($"Wrong realm. Expected {Options.Realm} received {realm}");
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
                        var algodHttpClient = HttpClientConfigurator.ConfigureHttpClient(Options.AlgodServer, Options.AlgodServerToken, Options.AlgodServerHeader);
                        var algodClient = new Algorand.Algod.DefaultApi(algodHttpClient);

                        var c = await algodClient.GetStatusAsync();
                        if (c != null)
                        {
                            t = DateTimeOffset.UtcNow;
                            block = (ulong)c.LastRound;
                        }
                        estimatedCurrentBlock = block;
                    }

                    if (tr.Tx.LastValid.Value < estimatedCurrentBlock)
                    {
                        throw new UnauthorizedException("Session timed out");
                    }
                    expiration = DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds((tr.Tx.LastValid.Value - estimatedCurrentBlock) * Options.MsPerBlock);
                }

                var user = tr.Tx.Sender.ToString();
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
                    claims.Add(new Claim("AlgoValidFrom", tr.Tx.FirstValid.Value.ToString()));
                    claims.Add(new Claim("AlgoValidUntil", tr.Tx.LastValid.Value.ToString()));
                }

                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }
            catch (UnauthorizedException e)
            {
                if (Options.EmptySuccessOnFailure)
                {
                    if (Options.Debug)
                    {
                        logger.LogDebug(e.Message);
                    }

                    var user = "";
                    var claims = new List<Claim>() {
                        new Claim(ClaimTypes.NameIdentifier,user),
                        new Claim(ClaimTypes.Name,user),
                    };

                    var identity = new ClaimsIdentity(claims, Scheme.Name);
                    var principal = new ClaimsPrincipal(identity);
                    var ticket = new AuthenticationTicket(principal, Scheme.Name);

                    return AuthenticateResult.Success(ticket);
                }
                else
                {

                    if (Options.Debug)
                    {
                        logger.LogError(e.Message);
                    }

                    return AuthenticateResult.Fail(e.Message);
                }

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