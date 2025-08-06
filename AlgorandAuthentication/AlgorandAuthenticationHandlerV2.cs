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
using ISystemClock = Microsoft.AspNetCore.Authentication.ISystemClock;

namespace AlgorandAuthenticationV2
{
    /// <summary>
    /// This class handles AlgorandAuthentication and allows services to communicate between each other in the simplest possible secure way.
    /// </summary>
    public class AlgorandAuthenticationHandlerV2 : AuthenticationHandler<AlgorandAuthenticationOptionsV2>, IAuthenticationRequestHandler, IAuthenticationHandler
    {
        public const string ID = "AlgorandAuthentication";
        public const string AuthPrefix = "SigTx ";
        private readonly ILogger<AlgorandAuthenticationHandlerV2> logger;
        private static DateTimeOffset? t;
        private static ulong block;
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
            UrlEncoder encoder,
            ISystemClock clock) : base(options, loggerFactory, encoder, clock)
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
                    logger.LogDebug($"Auth header: {Request.Headers[header]}");
                }
                var auth = Request.Headers[header].ToString();
                if (!auth.StartsWith(AuthPrefix))
                {
                    throw new UnauthorizedException($"Authorization header does not start with prefix {AuthPrefix}");
                }
                var tx = Convert.FromBase64String(auth.Replace(AuthPrefix, ""));
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
            Algorand.Algod.Model.Account? account = null;
            try
            {
                account = await algodClient.AccountInformationAsync(tr.Tx.Sender.EncodeAsString());

            }
            catch
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
                var network = Options.AllowedNetworks[networkHash];
                ulong estimatedCurrentBlock;
                if (t.HasValue && t.Value.AddHours(1) > DateTimeOffset.UtcNow)
                {
                    estimatedCurrentBlock = Convert.ToUInt64((DateTimeOffset.UtcNow - t.Value).TotalSeconds) / 5 + block;
                }
                else
                {
                    var algodHttpClient = HttpClientConfigurator.ConfigureHttpClient(network.Server, network.Token, network.Header);
                    var algodClient = new Algorand.Algod.DefaultApi(algodHttpClient);

                    var c = await algodClient.GetStatusAsync();
                    if (c != null)
                    {
                        t = DateTimeOffset.UtcNow;
                        block = (ulong)c.LastRound;
                    }
                    estimatedCurrentBlock = block;
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
    }
}