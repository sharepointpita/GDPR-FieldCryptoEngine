using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Yunify.Security.Encryption.KeyStore;

namespace Yunify.Security.Encryption.Provider
{
    public class AzureKeyVaultEncryptionProvider : IEncryptionProvider
    {

        readonly IAzureKeyVaultKeyStore _azureKeyVaultKeyStore;

        public AzureKeyVaultEncryptionProvider(IAzureKeyVaultKeyStore azureKeyVaultKeyStore)
        {
            _azureKeyVaultKeyStore = azureKeyVaultKeyStore;
        }

        public async Task<string> EncryptAsync(string userId, byte[] bytesToEncrypt)
        {
            var key = await _azureKeyVaultKeyStore.GetKeyAsync(userId) ?? await _azureKeyVaultKeyStore.CreateKeyAsync(userId);

            using (RSA rsaa = RSA.Create())
            {
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Modulus = key.Key.N;
                rsaParameters.Exponent = key.Key.E;
                rsaa.ImportParameters(rsaParameters);

                var encryptedData = await _azureKeyVaultKeyStore.KeyVaultClient.EncryptAsync(
                                        keyIdentifier: key.KeyIdentifier.Identifier
                                        , algorithm: JsonWebKeyEncryptionAlgorithm.RSAOAEP
                                        , plainText: bytesToEncrypt);


                string base64Enc = Convert.ToBase64String(encryptedData.Result);
                return base64Enc;
            }
        }

        public async Task<byte[]> DecryptAsync(string userId, string txtToDecryptBase64Enc)
        {
            var key = await _azureKeyVaultKeyStore.GetKeyAsync(userId);

            using (RSA rsaa = RSA.Create())
            {
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Modulus = key.Key.N;
                rsaParameters.Exponent = key.Key.E;
                rsaa.ImportParameters(rsaParameters);

                var decryptedData = await _azureKeyVaultKeyStore.KeyVaultClient.DecryptAsync(
                                        keyIdentifier: key.KeyIdentifier.Identifier
                                        , algorithm: JsonWebKeyEncryptionAlgorithm.RSAOAEP
                                        , cipherText: Convert.FromBase64String(txtToDecryptBase64Enc));

                return decryptedData.Result;
            }
        }
       
    }
}