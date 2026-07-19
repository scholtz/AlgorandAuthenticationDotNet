using Algorand;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
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

namespace AlgorandAuthenticationV2
{
    /// <summary>
    /// This class handles AlgorandAuthentication and allows services to communicate between each other in the simplest possible secure way.
    /// </summary>
    public class AlgorandAuthenticationHandlerV2 : AuthenticationHandler<AlgorandAuthenticationOptionsV2>, IAuthenticationRequestHandler, IAuthenticationHandler
    {
        public const string ID = "AlgorandAuthentication";
        public const string BearerPrefix = "bearer ";
        public const string AuthPrefix = "SigTx ";
        private readonly ILogger<AlgorandAuthenticationHandlerV2> logger;
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTimeOffset t, ulong block)> blockCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, (DateTimeOffset, ulong)>();
        private readonly byte[] EmptySig;
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        /// <param name="encoder"></param>
        public AlgorandAuthenticationHandlerV2(
            IOptionsMonitor<AlgorandAuthenticationOptionsV2> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder) : base(options, loggerFactory, encoder)
        {
            this.logger = loggerFactory.CreateLogger<AlgorandAuthenticationHandlerV2>();
            EmptySig = new byte[64];
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
        /// 
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return await HandleAuthenticateWithRequestAsync(Request, Options);
        }
        /// <summary>
        /// HandleAuthenticateAsync available for tests
        /// </summary>
        /// <param name="Request"></param>
        /// <returns></returns>
        public async Task<AuthenticateResult> HandleAuthenticateWithRequestAsync(HttpRequest Request, AlgorandAuthenticationOptionsV2 Options)
        {
            try
            {
                var header = Request.Headers.ContainsKey("Authorization") ? "Authorization" :
                    Request.Headers.ContainsKey("authorization") ? "authorization" : null;

                if (string.IsNullOrEmpty(header))
                    throw new UnauthorizedException("No authorization header");

                if (Options.Debug)
                {
                    // Only a prefix/length is logged - the header is a signed transaction, never a
                    // private key, but it is a replayable credential and should not be fully logged.
                    logger.LogDebug($"Auth header received. Length: {Request.Headers[header].ToString().Length}, Prefix: {Truncate(Request.Headers[header].ToString(), 16)}");
                }
                var auth = Request.Headers[header].ToString();
                if (auth.ToLower().StartsWith(BearerPrefix))
                {
                    auth = auth.Substring(BearerPrefix.Length);
                }
                if (!auth.StartsWith(AuthPrefix))
                {
                    throw new UnauthorizedException($"Authorization header does not start with prefix {AuthPrefix}");
                }
                auth = auth.Substring(AuthPrefix.Length);
                auth = auth.Replace(" ", "+");

                var tx = Convert.FromBase64String(auth);
                var tr = Algorand.Utils.Encoder.DecodeFromMsgPack<Algorand.Algod.Model.Transactions.SignedTransaction>(tx);
                if (tr.Tx == null)
                {
                    throw new UnauthorizedException("Signature is invalid. Does not contain tx.");
                }


                if (tr.Sig != null)
                {
                    return await AlgorandAuthenticationHandlerV2.HandleAuthenticateWithRequestSingleSigAsync(Options, tr);
                }
                else if (tr.MSig != null)
                {
                    return await HandleAuthenticateWithRequestMultiSigAsync(Options, tr);
                }
                else
                {
                    throw new UnauthorizedException("Signature is invalid. Does not contain sig or msig.");
                }

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
                        // Lets downstream authorization policies positively detect that this ticket is an
                        // EmptySuccessOnFailure fallback rather than a genuinely verified signature, instead of
                        // having to infer it from an empty NameIdentifier.
                        new Claim("AlgoAuthFallback","true"),
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
        private static async Task<Algorand.Address> AuthAddress(AlgorandAuthenticationOptionsV2 Options, Algorand.Algod.Model.Transactions.SignedTransaction tr)
        {
            var networkHash = Convert.ToBase64String(tr.Tx.GenesisHash.Bytes);
            if (!Options.AllowedNetworks.ContainsKey(networkHash))
            {
                throw new Exception($"This transaction was done using {networkHash} network but it is not configured in allowed networks");
            }
            var network = Options.AllowedNetworks[networkHash];
            if (string.IsNullOrEmpty(network.Server)) // if algod server is not configured do not process rekeying
            {
                return tr.Tx.Sender;
            }
            var algodHttpClient = HttpClientConfigurator.ConfigureHttpClient(network.Server, network.Token, network.Header);
            var algodClient = new Algorand.Algod.DefaultApi(algodHttpClient);
#nullable enable
            Algorand.Algod.Model.Account? account = null;
#nullable disable
            try
            {
                account = await algodClient.AccountInformationAsync(tr.Tx.Sender.EncodeAsString());

            }
            catch (Algorand.ApiException e) when (e.StatusCode == 404)
            {
                // Confirmed by the algod node that the account genuinely does not exist on-chain yet -
                // safe to treat as a brand-new, never-rekeyed account when AllowEmptyAccounts is enabled.
                if (Options.AllowEmptyAccounts)
                {
                    account = new Algorand.Algod.Model.Account
                    {
                        AuthAddr = tr.Tx.Sender,
                        Address = tr.Tx.Sender,
                        Amount = 0
                    };
                }
            }
            // Any other failure (timeout, DNS, 5xx, transport error, etc.) must fail closed rather than
            // silently assuming the account was never rekeyed - see RISK-001. Doing otherwise would let a
            // signature from an old/compromised key that was rekeyed away from succeed during an algod outage.
            if (account.Amount == 0)
            {
                if (Options.AllowEmptyAccounts)
                {
                    account = new Algorand.Algod.Model.Account
                    {
                        AuthAddr = tr.Tx.Sender,
                        Address = tr.Tx.Sender,
                        Amount = 0
                    };
                }
            }
            if (account == null)
            {
                throw new UnauthorizedException("Empty accounts are not allowed");
            }
            return account.AuthAddr ?? tr.Tx.Sender;
        }
        /// <summary>
        /// HandleAuthenticateAsync for single sig tx
        /// </summary>
        /// <param name="Request"></param>
        /// <returns></returns>
        private static async Task<AuthenticateResult> HandleAuthenticateWithRequestSingleSigAsync(AlgorandAuthenticationOptionsV2 Options, Algorand.Algod.Model.Transactions.SignedTransaction tr)
        {

            var sender = await AlgorandAuthenticationHandlerV2.AuthAddress(Options, tr);
            if (!AlgorandAuthenticationHandlerV2.Verify(sender.Bytes, tr.Tx.BytesToSign(), tr.Sig.Bytes))
            {
                throw new UnauthorizedException("Signature is invalid");
            }
            return await AlgorandAuthenticationHandlerV2.VerifyCommon(Options, tr);
        }

        /// <summary>
        /// HandleAuthenticateAsync for multi sig tx
        /// </summary>
        /// <param name="Request"></param>
        /// <returns></returns>
        private async Task<AuthenticateResult> HandleAuthenticateWithRequestMultiSigAsync(AlgorandAuthenticationOptionsV2 Options, Algorand.Algod.Model.Transactions.SignedTransaction tr)
        {
            // validate all signatures

            var checkedSet = new HashSet<string>(); // check if signature is double inserted
            var validSignatures = 0;
            foreach (var subsig in tr.MSig.Subsigs)
            {
                var b64 = Convert.ToBase64String(subsig.key.GetEncoded());
                if (checkedSet.Contains(b64))
                {
                    throw new UnauthorizedException("Signature is invalid. Address has been already used.");
                }
                checkedSet.Add(b64);
                if (subsig.sig == null || subsig.sig.Bytes.SequenceEqual(EmptySig))
                {
                    continue;
                }
                if (AlgorandAuthenticationHandlerV2.Verify(subsig.key.GetEncoded(), tr.Tx.BytesToSign(), subsig.sig.Bytes))
                {
                    validSignatures++;
                }
                else
                {
                    throw new UnauthorizedException("Signature is invalid");
                }
            }
            // check if all signators are valid signators

            var multiAddress = new MultisigAddress(tr.MSig.Version, tr.MSig.Threshold, tr.MSig.Subsigs.Select(t => t.key.GetEncoded()).ToList());
            var sender = await AlgorandAuthenticationHandlerV2.AuthAddress(Options, tr);
            if (sender.EncodeAsString() != multiAddress.ToAddress().EncodeAsString())
            {
                throw new UnauthorizedException("Signature is invalid. Sender of signed transaction is not the multisig object provided");
            }

            // check if threshold of signatures is ok
            if (tr.MSig.Threshold > validSignatures)
            {
                throw new UnauthorizedException($"Signature is invalid. Threshold of signatures ({tr.MSig.Threshold}) has not been met ({tr.MSig.Subsigs.Where(s => s.sig != null && !s.sig.Bytes.SequenceEqual(EmptySig)).Count()}).");
            }

            return await AlgorandAuthenticationHandlerV2.VerifyCommon(Options, tr);
        }
        private static async Task<AuthenticateResult> VerifyCommon(AlgorandAuthenticationOptionsV2 Options, Algorand.Algod.Model.Transactions.SignedTransaction tr)
        {

            var networkHash = Convert.ToBase64String(tr.Tx.GenesisHash.Bytes);
            if (!Options.AllowedNetworks.ContainsKey(networkHash))
            {
                throw new UnauthorizedException($"Invalid Network. Received {networkHash}. Configured {string.Join(",", Options.AllowedNetworks.Keys)}");
            }

            if (Options.Realms.Any())
            {
                if (tr.Tx.Note == null)
                {
                    throw new UnauthorizedException($"Wrong realm. Expected one of {string.Join(", ", Options.Realms)} received no note.");
                }
                var realm = Encoding.ASCII.GetString(tr.Tx.Note);
                if (!Options.Realms.Contains(realm))
                {
                    // todo: add meaningful message
                    throw new UnauthorizedException($"Wrong realm. Expected one of {string.Join(", ", Options.Realms)} received {realm}");
                }
            }
            else
            if (!string.IsNullOrEmpty(Options.Realm))
            {
                if (tr.Tx.Note == null)
                {
                    throw new UnauthorizedException($"Wrong realm. Expected {Options.Realm} received no note.");
                }
                var realm = Encoding.ASCII.GetString(tr.Tx.Note);
                if (Options.Realm != realm)
                {
                    // todo: add meaningful message
                    throw new UnauthorizedException($"Wrong realm. Expected {Options.Realm} received {realm}");
                }
            }
            else
            {
                // Both Realm and Realms are empty - this removes domain separation between different
                // applications sharing the same AllowedNetworks configuration (RISK-007). Fail closed
                // instead of silently accepting any realm/no realm at all.
                throw new UnauthorizedException("No realm configured. At least one of Realm or Realms must be set to enforce domain separation.");
            }


            DateTimeOffset? expiration = null;
            if (Options.CheckExpiration)
            {
                var network = Options.AllowedNetworks[networkHash];
                ulong estimatedCurrentBlock;
                // Cache is partitioned per network genesis hash so that a round number fetched for one
                // configured network is never used to estimate expiration for a different network (RISK-004).
                if (blockCache.TryGetValue(networkHash, out var cached) && cached.t.AddHours(1) > DateTimeOffset.UtcNow)
                {
                    estimatedCurrentBlock = Convert.ToUInt64((DateTimeOffset.UtcNow - cached.t).TotalSeconds) / 5 + cached.block;
                }
                else
                {
                    var algodHttpClient = HttpClientConfigurator.ConfigureHttpClient(network.Server, network.Token, network.Header);
                    var algodClient = new Algorand.Algod.DefaultApi(algodHttpClient);

                    var c = await algodClient.GetStatusAsync();
                    if (c != null)
                    {
                        cached = (DateTimeOffset.UtcNow, (ulong)c.LastRound);
                        blockCache[networkHash] = cached;
                    }
                    estimatedCurrentBlock = cached.block;
                }

                if (tr.Tx.LastValid < estimatedCurrentBlock)
                {
                    throw new UnauthorizedException("Session timed out");
                }
                expiration = DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds((tr.Tx.LastValid - estimatedCurrentBlock) * network.MsPerBlock);
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
                claims.Add(new Claim("AlgoValidFrom", tr.Tx.FirstValid.ToString()));
                claims.Add(new Claim("AlgoValidUntil", tr.Tx.LastValid.ToString()));
            }

            var identity = new ClaimsIdentity(claims, ID);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, ID);

            return AuthenticateResult.Success(ticket);
        }
        private static bool Verify(byte[] address, byte[] message, byte[] sig)
        {

            var signer = new Ed25519Signer();
            var pk = new Ed25519PublicKeyParameters(address, 0);
            signer.Init(false, pk);
            signer.BlockUpdate(message.ToArray(), 0, message.ToArray().Length);
            return signer.VerifySignature(sig);
        }
        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value;
            }
            return value.Substring(0, maxLength) + "...";
        }
    }
}