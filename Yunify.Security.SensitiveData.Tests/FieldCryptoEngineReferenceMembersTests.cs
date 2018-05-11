using System;
using Xunit;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.SensitiveData.Tests
{
    public class FieldCryptoEngineReferenceMembersTests
    {

        readonly FieldCryptoEngine _engine;

        public FieldCryptoEngineReferenceMembersTests()
        {
            var keyGenerator = new RsaKeyGenerator();
            var keyStore = new InMemoryRsaKeyStore(keyGenerator);
            var provider = new RsaEncryptionProvider(keyStore);
            _engine = new FieldCryptoEngine(provider);
        }


        [Fact]
        public void Encrypt_should_encrypt_reference_field_with_sensitivedata_attribute()
        {

            string firstChildName = "Baby Doe";

            var person = new Adult  {Name= "John Doe", FirstChild = new Child() { Name = "Baby Doe" } };
            var userId = Guid.NewGuid().ToString();

            _engine.Encrypt(userId, person);

            Assert.Null(person.FirstChild);
            Assert.NotNull(person.FirstChildEncrypted);

            _engine.Decrypt(userId, person);

            Assert.NotNull(person.FirstChild);
            Assert.Null(person.FirstChildEncrypted);
            Assert.Equal(firstChildName, person.FirstChild.Name);
        }

        

        public class Adult
        {
            [SensitiveData]
            public string Name { get; set; }

            [SensitiveData(SerializeToMember =nameof(FirstChildEncrypted))]
            public Child FirstChild { get; set;}

            public string FirstChildEncrypted { get; set; }

            public Adult()
            {
            }
        }

        public class Child
        {
            public string Name { get; set; }
        }

    }

    
}
