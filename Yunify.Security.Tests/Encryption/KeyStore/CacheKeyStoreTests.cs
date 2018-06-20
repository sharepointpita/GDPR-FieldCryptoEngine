using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System;
using System.Reflection;
using System.Threading.Tasks;
using Xunit;
using Yunify.Security.Encryption.KeyStore;

namespace Yunify.Security.Tests.Encryption.KeyStore
{
    public class CacheKeyStoreTests : KeyStoreTestBase
    {
        private readonly IKeyStore<string> _sut;

        public CacheKeyStoreTests()
        {

            _sut = new CacheKeyStore<string>(
                 SimpleKeyStore
                , new MemoryDistributedCache(new CacheOptions()));
        }


        [Fact]
        public async Task CreateKeyAsync_should_add_key_to_cache()
        {
            Guid keyId = Guid.NewGuid();

            await _sut.CreateKeyAsync(keyId.ToString());

            Assert.Equal(1, GetCacheCount());
        }

        [Fact]
        public async Task DeleteKeyAsync_should_remove_key_from_cache()
        {
            Guid keyId = Guid.NewGuid();

            await _sut.CreateKeyAsync(keyId.ToString());

            Assert.Equal(1, GetCacheCount());

            await _sut.DeleteKeyAsync(keyId.ToString());

            Assert.Equal(0, GetCacheCount());
        }


        [Fact]
        public async Task GetKeyAsync_should_add_key_to_cache_if_not_exists()
        {
            Guid keyId = Guid.NewGuid();

            await SimpleKeyStore.CreateKeyAsync(keyId.ToString());

            Assert.Equal(0, GetCacheCount());

            await _sut.GetKeyAsync(keyId.ToString());

            Assert.Equal(1, GetCacheCount());
        }

        [Fact]
        public async Task GetKeyAsync_should_return_key_from_cache_if_entry_exists()
        {
            Guid keyId = Guid.NewGuid();

            await SimpleKeyStore.CreateKeyAsync(keyId.ToString());

            Assert.Equal(0, GetCacheCount());

            await _sut.GetKeyAsync(keyId.ToString());

            Assert.Equal(1, GetCacheCount());

            await _sut.GetKeyAsync(keyId.ToString());

            Assert.Equal(1, GetCacheCount());
        }

        private int GetCacheCount()
        {
            FieldInfo fi =
                typeof(CacheKeyStore<string>).GetField("_cache", BindingFlags.NonPublic | BindingFlags.Instance);

             var val = (MemoryDistributedCache) fi.GetValue(_sut);

            FieldInfo fiMemCache =
                typeof(MemoryDistributedCache).GetField("_memCache", BindingFlags.NonPublic | BindingFlags.Instance);

            var memCache = (MemoryCache)fiMemCache.GetValue(val);

            return memCache.Count;
        }


    }

    public class CacheOptions : IOptions<MemoryDistributedCacheOptions>
    {
        public MemoryDistributedCacheOptions Value { get; }

        public CacheOptions()
        {
            Value = new MemoryDistributedCacheOptions();
            Value.SizeLimit = 1000;
        }
    }
}
