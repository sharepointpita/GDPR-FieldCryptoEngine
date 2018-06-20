using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.SensitiveData.Tests
{
    public class SensitiveDataKeyIdTests
    {
        readonly FieldCryptoEngine _engine;

        public SensitiveDataKeyIdTests()
        {
            var keyGenerator = new RsaKeyGenerator();
            var keyStore = new InMemoryRsaKeyStore(keyGenerator);
            var provider = new RsaEncryptionProvider(keyStore);
            _engine = new FieldCryptoEngine(provider);
        }


        [Fact]
        public async Task Encrypt_should_encrypt_and_decrypt_with_string_sensitivedatakeyid_attribute()
        {
            var person = new PersonCase1
            {
                SocialSecurityNumber = "123qwe",
                FirstName = "John"
            };

            await _engine.EncryptAsync(person);

            Assert.NotEqual("John", person.FirstName);

            await _engine.DecryptAsync(person);

            Assert.Equal("John", person.FirstName);
        }

        [Fact]
        public async Task Encrypt_should_encrypt_and_decrypt_with_int_sensitivedatakeyid_attribute()
        {
            var person = new PersonCase4
            {
                Id = 999,
                FirstName = "John"
            };

            await _engine.EncryptAsync(person);

            Assert.NotEqual("John", person.FirstName);

            await _engine.DecryptAsync(person);

            Assert.Equal("John", person.FirstName);
        }

        [Fact]
        public async Task Encrypt_should_throw_ex_when_multiple_sensitivedatakeyid_attribute_defined()
        {
            var person = new PersonCase2
            {
                SocialSecurityNumber = "123qwe",
                Age = 22,
                FirstName = "John"
            };

            await Assert.ThrowsAsync<Exception>(() => _engine.EncryptAsync(person));
        }

        [Fact]
        public async Task Encrypt_should_throw_ex_when_no_sensitivedatakeyid_is_defined()
        {
            var person = new PersonCase3
            {
                Id = 1,
                FirstName = "John"
            };

            await Assert.ThrowsAsync<Exception>(() => _engine.EncryptAsync(person));
        }

        [Fact]
        public async Task Encrypt_should_throw_ex_when_sensitivedatakeyid_is_null_or_empty()
        {
            var person = new PersonCase4
            {
                Id = null,
                FirstName = "John"
            };

            await Assert.ThrowsAsync<Exception>(() => _engine.EncryptAsync(person));
        }



        private class PersonCase1
        {
            [SensitiveDataKeyId]
            public string SocialSecurityNumber { get; set; }

            [SensitiveData]
            public string FirstName { get; set; }
        }

        private class PersonCase2
        {
            [SensitiveDataKeyId]
            public string SocialSecurityNumber { get; set; }

            [SensitiveDataKeyId]
            public int Age { get; set; }

            [SensitiveData]
            public string FirstName { get; set; }
        }

        private class PersonCase3
        {
        
            public long Id { get; set; }

            [SensitiveData]
            public string FirstName { get; set; }
        }

        private class PersonCase4
        {
            [SensitiveDataKeyId]
            public long? Id { get; set; }

            [SensitiveData]
            public string FirstName { get; set; }
        }
    }
}
