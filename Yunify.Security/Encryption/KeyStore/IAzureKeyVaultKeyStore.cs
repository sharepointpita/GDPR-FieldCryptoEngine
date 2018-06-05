using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using System;
using System.Threading.Tasks;

namespace Yunify.Security.Encryption.KeyStore
{
    public interface IAzureKeyVaultKeyStore : IKeyStore<KeyBundle>
    {
        KeyVaultClient KeyVaultClient { get; }
    }
}
