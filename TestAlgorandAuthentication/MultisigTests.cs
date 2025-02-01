using Algorand;
using Algorand.Algod;
using Algorand.Algod.Model.Transactions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using NUnit.Framework.Internal;
using System.Text.Encodings.Web;

namespace TestAlgorandAuthentication
{
    public class Tests
    {
        private Algorand.Algod.Model.Account acc1;
        private Algorand.Algod.Model.Account acc2;
        private Algorand.Algod.Model.Account acc3;
        private MultisigAddress multiAddress;
        private DefaultApi algodApiInstance;
        private readonly string ALGOD_API_ADDR = "https://testnet-api.algonode.cloud/";
        private readonly string ALGOD_API_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private readonly string Realm = "TEST#ARC14";
        [SetUp]
        public void Setup()
        {
            var httpClient = HttpClientConfigurator.ConfigureHttpClient(ALGOD_API_ADDR, ALGOD_API_TOKEN);
            algodApiInstance = new DefaultApi(httpClient);

            acc1 = new Algorand.Algod.Model.Account("gravity maid again grass ozone execute exotic vapor fringe snack club monitor where jar pyramid receive tattoo science scene high sound degree bless above good");
            acc2 = new Algorand.Algod.Model.Account("move sell junior vast verb stove bracket filter place child fame bone story science miss injury put cancel already session cheap furnace void able minimum");
            acc3 = new Algorand.Algod.Model.Account("pencil ostrich net alpha need vivid elevator gadget bundle meadow flash hamster pig young ten clown before grace arch tennis absent knock peanut ability alarm");
            multiAddress = new MultisigAddress(1, 2, new List<byte[]> { acc1.Address.Bytes, acc2.Address.Bytes, acc3.Address.Bytes });
        }

        [Test]
        public async Task ValidateMultisigTransaction()
        {
            var transParams = await algodApiInstance.TransactionParamsAsync();
            var payment = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(multiAddress.ToAddress(), multiAddress.ToAddress(), 0, Realm, transParams);

            // sign with 2 addresses (2 of 3 threshold)
            var signedTx1 = payment.Sign(multiAddress, acc1);
            var signedTx2 = payment.Sign(multiAddress, acc2);
            var signedTx = SignedTransaction.MergeMultisigTransactions(signedTx1, signedTx2);
            var auth = "SigTx " + Convert.ToBase64String(Algorand.Utils.Encoder.EncodeToMsgPackOrdered(signedTx));

            var au = new AlgorandAuthentication.AlgorandAuthenticationOptions() { Debug = true, AlgodServer = ALGOD_API_ADDR, AlgodServerToken = ALGOD_API_TOKEN, Realm = Realm, CheckExpiration = false, NetworkGenesisHash = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=" };
            var monitor = Mock.Of<IOptionsMonitor<AlgorandAuthentication.AlgorandAuthenticationOptions>>(_ => _.CurrentValue == au);

            var loggerFactory = LoggerFactory.Create(c => c.AddConsole().SetMinimumLevel(LogLevel.Debug));

            var urlEncoder = UrlEncoder.Default;
            var clock = new RealSystemClock();
            var handler = new AlgorandAuthentication.AlgorandAuthenticationHandler(monitor, loggerFactory, urlEncoder, clock);

            var context = new DefaultHttpContext();
            context.Request.Headers.Authorization = auth;

            var result = await handler.HandleAuthenticateWithRequestAsync(context.Request, au);

            Assert.That(result, Is.Not.Null);
            Assert.That(result.Succeeded, Is.True);
        }

        [Test]
        public async Task ValidateSinglesigTransaction()
        {
            var transParams = await algodApiInstance.TransactionParamsAsync();
            var payment = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(acc1.Address, multiAddress.ToAddress(), 0, Realm, transParams);
            var signedTx = payment.Sign(acc2); // rekeyd
            var auth = "SigTx " + Convert.ToBase64String(Algorand.Utils.Encoder.EncodeToMsgPackOrdered(signedTx));

            var au = new AlgorandAuthentication.AlgorandAuthenticationOptions() { Debug = true, AlgodServer = ALGOD_API_ADDR, AlgodServerToken = ALGOD_API_TOKEN, Realm = Realm, CheckExpiration = false, NetworkGenesisHash = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=" };
            var monitor = Mock.Of<IOptionsMonitor<AlgorandAuthentication.AlgorandAuthenticationOptions>>(_ => _.CurrentValue == au);

            var loggerFactory = LoggerFactory.Create(c => c.AddConsole().SetMinimumLevel(LogLevel.Debug));

            var urlEncoder = UrlEncoder.Default;
            var clock = new RealSystemClock();
            var handler = new AlgorandAuthentication.AlgorandAuthenticationHandler(monitor, loggerFactory, urlEncoder, clock);

            var context = new DefaultHttpContext();
            context.Request.Headers.Authorization = auth;

            var result = await handler.HandleAuthenticateWithRequestAsync(context.Request, au);

            Assert.That(result, Is.Not.Null);
            Assert.That(result.Succeeded, Is.True);
        }
    }

    public class RealSystemClock : Microsoft.AspNetCore.Authentication.ISystemClock
    {
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }
    class Events
    {

    }
    class EventsType
    {

    }

}