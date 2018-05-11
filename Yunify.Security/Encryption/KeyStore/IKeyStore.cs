using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Yunify.Security.Encryption.KeyStore
{
    /// <summary>
    /// T is the Key Type
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IKeyStore<T> 
    {
        T CreateKeyAsync(string keyId);

        T GetKeyAsync(string keyId);

        void DeleteKeyAsync(string keyId);
    }
}
