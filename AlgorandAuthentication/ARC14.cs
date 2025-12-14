using Algorand;
using Algorand.Algod.Model;
using Algorand.Algod.Model.Transactions;
using AVM.ClientGenerator.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;

namespace AlgorandAuthentication
{
    public class ARC14
    {
        /// <summary>
        /// Creates a payment transaction payload using the specified sender, signer, realm, and network transaction
        /// parameters.
        /// </summary>
        /// <param name="sender">The address of the account initiating the transaction. This account will be used as the sender of the
        /// payment transaction.</param>
        /// <param name="signer">The address of the account that will sign the transaction. This may differ from the sender in cases such as
        /// delegated signatures.</param>
        /// <param name="realm">A string that specifies the application or domain context for the transaction. Used to distinguish
        /// transactions across different logical realms.</param>
        /// <param name="transParams">The current network transaction parameters to use when constructing the transaction. Must not be null.</param>
        /// <returns>A <see cref="Algorand.Algod.Model.Transactions.Transaction"/> object representing the constructed payment
        /// transaction payload.</returns>
        public static Algorand.Algod.Model.Transactions.Transaction CreatePayload(Address sender, Address signer, string realm, TransactionParametersResponse transParams)
        {
            return PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(sender, signer, 0, realm, transParams);
        }
        /// <summary>
        /// Creates a signed transaction header for the specified Algorand account and transaction parameters within the
        /// given realm.
        /// </summary>
        /// <param name="signedTransaction"></param>
        /// <returns></returns>
        public static string CreateHeader(SignedTransaction signedTransaction)
        {
            return "SigTx " + Convert.ToBase64String(Algorand.Utils.Encoder.EncodeToMsgPackOrdered(signedTransaction));
        }
        /// <summary>
        /// Creates a signed transaction header for the specified Algorand account and transaction parameters within the
        /// given realm.
        /// </summary>
        /// <param name="algo25Account">The Algorand account used to sign the transaction. The account's address and rekeyed address are used to
        /// construct the payload. Cannot be null.</param>
        /// <param name="realm">The logical realm or context for which the transaction header is being created. This value is included in
        /// the payload.</param>
        /// <param name="transParams">The transaction parameters to use when constructing the payload. Cannot be null.</param>
        /// <returns>A string representing the signed transaction header for the specified account and parameters.</returns>
        public static string CreateHeader(Algorand.Algod.Model.Account algo25Account, string realm, TransactionParametersResponse transParams)
        {
            var payload = CreatePayload(algo25Account.RekeyedTo ?? algo25Account.Address, algo25Account.Address, realm, transParams);
            var signedTransaction = payload.Sign(algo25Account);
            return CreateHeader(signedTransaction);
        }
    }
}
