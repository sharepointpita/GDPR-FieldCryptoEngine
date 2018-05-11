using System.Collections.Generic;
using Org.BouncyCastle.Crypto;
using Yunify.Security.Encryption.Asymmentric.RSA;

namespace Yunify.Security.Encryption.KeyStore
{
    public class InMemoryRsaKeyStore : IKeyStore<AsymmetricCipherKeyPair>
    {

        private readonly IRsaKeyGenerator _keyGenerator;
        private readonly Dictionary<string, AsymmetricCipherKeyPair> _keys = new Dictionary<string, AsymmetricCipherKeyPair>();


        public InMemoryRsaKeyStore(IRsaKeyGenerator keyGenerator)
        {
            _keyGenerator = keyGenerator;
        }
        

        public AsymmetricCipherKeyPair CreateKeyAsync(string keyId)
        {
            var key = _keyGenerator.GenerateRsaKey(RsaKeySize.R3072);
            if (!_keys.ContainsKey(keyId))
            {
                _keys.Add(keyId,key);
            }
            return key;
        }

        public void DeleteKeyAsync(string keyId)
        {
            if (_keys.ContainsKey(keyId))
            {
                _keys.Remove(keyId);
            }
        }

        public AsymmetricCipherKeyPair GetKeyAsync(string keyId)
        {
            if (_keys.ContainsKey(keyId))
            {
                return _keys[keyId];
            }
            else
            {
                return null;
            }
        }
    }
}
