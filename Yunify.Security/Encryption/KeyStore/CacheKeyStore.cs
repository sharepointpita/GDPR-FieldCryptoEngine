using MessagePack;
using Microsoft.Extensions.Caching.Distributed;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Yunify.Security.Encryption.KeyStore
{
    public class CacheKeyStore<T> : IKeyStore<T>
    {
        private readonly IDistributedCache _cache;
        private readonly IKeyStore<T> _keystore;

        private static readonly ConcurrentDictionary<string, object> _locks =
            new ConcurrentDictionary<string, object>();

        public CacheKeyStore(IKeyStore<T> keyStore, IDistributedCache cache)
        {
            _keystore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        }


        public async Task<T> CreateKeyAsync(string keyId)
        {
            T key = await _keystore.CreateKeyAsync(keyId);
            byte[] keyInBytes = MessagePackSerializer.Typeless.Serialize(key);

            try
            {
                await _cache.SetAsync(keyId, keyInBytes);
            }
            catch (Exception)
            {
            }

            return key;
        }

        public async Task DeleteKeyAsync(string keyId)
        {
            await _keystore.DeleteKeyAsync(keyId);

            try
            {
                await _cache.RemoveAsync(keyId);
            }
            catch (Exception)
            {

            }
        }

        public async Task<T> GetKeyAsync(string keyId)
        {
            T key;
            byte[] keyInCache = await _cache.GetAsync(keyId);
            if (keyInCache != null)
            {
                key = (T)MessagePackSerializer.Typeless.Deserialize(keyInCache);
            }
            else
            {
                key = await _keystore.GetKeyAsync(keyId);

                keyInCache = MessagePackSerializer.Typeless.Serialize(key);

                await _cache.SetAsync(keyId, keyInCache);
            }

            return key;
        }
    }
}
