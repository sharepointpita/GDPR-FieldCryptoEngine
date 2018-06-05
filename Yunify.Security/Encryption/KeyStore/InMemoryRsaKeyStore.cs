using System.Collections.Generic;
using System.Threading.Tasks;
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
        

        public Task<AsymmetricCipherKeyPair> CreateKeyAsync(string keyId)
        {
            var key = _keyGenerator.GenerateRsaKey(RsaKeySize.R3072);
            if (!_keys.ContainsKey(keyId))
            {
                _keys.Add(keyId,key);
            }
            return Task.FromResult(key);
        }

        public Task DeleteKeyAsync(string keyId)
        {
            if (_keys.ContainsKey(keyId))
            {
                _keys.Remove(keyId);
            }
            return Task.CompletedTask;
        }

        public Task<AsymmetricCipherKeyPair> GetKeyAsync(string keyId)
        {
            if (_keys.ContainsKey(keyId))
            {
                return Task.FromResult(_keys[keyId]);
            }
            else
            {
                return null;
            }
        }
    }
}
