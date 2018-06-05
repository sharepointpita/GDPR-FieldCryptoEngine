using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Threading.Tasks;

namespace Yunify.Security.Encryption.KeyStore
{
    public class AzureKeyVaultStore : IAzureKeyVaultKeyStore
    {
        private string _vaultAddress;
        private string _clientId;
        private string _clientSecret;

        public KeyVaultClient KeyVaultClient { get; }

        public AzureKeyVaultStore(string vaultAddress, string clientId, string clientSecret)
        {
            _vaultAddress = vaultAddress;
            _clientId = clientId;
            _clientSecret = clientSecret;

            // Create a Key Vault client with an Active Directory authentication callback
            KeyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetAccessTokenAsync));
        }

        public async Task<KeyBundle> CreateKeyAsync(string keyId)
        {
            // Get the API key out of the vault
            var keybundle = await KeyVaultClient.CreateKeyAsync(_vaultAddress, keyId, "RSA");

            return keybundle;
        }

        public async Task DeleteKeyAsync(string keyId)
        {
            // Get the API key out of the vault
            await KeyVaultClient.DeleteKeyAsync(_vaultAddress, keyId);
        }
 

        public async Task<KeyBundle> GetKeyAsync(string keyId)
        {
            try
            {
                // Get the API key out of the vault
                var keybundle = await KeyVaultClient.GetKeyAsync(_vaultAddress, keyId);

                return keybundle;
            }
            catch (KeyVaultErrorException ex)
            {
                /* Key Not Found */
                if (ex.Body.Error.Code == "KeyNotFound")
                    return null;
                else
                    throw;
            }
        }

        private async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            var credential = new ClientCredential(_clientId, _clientSecret);
            var token = await authContext.AcquireTokenAsync(resource, credential);
            return token.AccessToken;
        }


    }


}
