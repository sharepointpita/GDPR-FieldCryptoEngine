using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Yunify.Security.Encryption.KeyStore;

namespace Yunify.Security.Tests
{
    public class KeyStoreTestBase
    {
        public SimpleKeyStore SimpleKeyStore { get; }

        public KeyStoreTestBase()
        {
            SimpleKeyStore = new SimpleKeyStore();
        }
    }

    public class SimpleKeyStore : IKeyStore<string>
    {
        private readonly Dictionary<string, string> _keys = new Dictionary<string, string>();

        public Task<string> CreateKeyAsync(string keyId)
        {
            if (!_keys.ContainsKey(keyId))
            {
                _keys.Add(keyId, "key_" + keyId);
            }
            return Task.FromResult("key_" + keyId);
        }

        public Task DeleteKeyAsync(string keyId)
        {
            if (_keys.ContainsKey(keyId))
            {
                _keys.Remove(keyId);
            }
            return Task.CompletedTask;
        }

        public Task<string> GetKeyAsync(string keyId)
        {
            if (_keys.ContainsKey(keyId))
            {
                return Task.FromResult(_keys[keyId]);
            }
            else
            {
                return Task.FromResult<string>(null);
            }
        }

    }
}
