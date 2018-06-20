using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Yunify.Security.Encryption.Symmetric.AES;

namespace Yunify.Security.Encryption.KeyStore
{
    public class InMemoryAesKeyStore : IKeyStore<AesKey>
    {
        private readonly IAesKeyGenerator _keyGenerator;
        private readonly Dictionary<string, AesKey> _keys = new Dictionary<string, AesKey>();

        public InMemoryAesKeyStore(IAesKeyGenerator keyGenerator)
        {
            _keyGenerator = keyGenerator;
        }

        public Task<AesKey> CreateKeyAsync(string keyId)
        {
            var key = _keyGenerator.GenerateAesKey(AesKeySize.A256);

            if (!_keys.ContainsKey(keyId))
            {
                _keys.Add(keyId, key);
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

        public Task<AesKey> GetKeyAsync(string keyId)
        {
            if (_keys.ContainsKey(keyId))
            {
                return Task.FromResult(_keys[keyId]);
            }
            else
            {
                return Task.FromResult<AesKey>(null);
            }
        }
    }
}
