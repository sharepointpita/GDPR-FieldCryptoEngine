using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Yunify.Security.Encryption.KeyStore
{
    /// <summary>
    /// T is the Key Type
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IKeyStore<T> 
    {
        Task<T> CreateKeyAsync(string keyId);

        Task<T> GetKeyAsync(string keyId);

        Task DeleteKeyAsync(string keyId);
    }
}
