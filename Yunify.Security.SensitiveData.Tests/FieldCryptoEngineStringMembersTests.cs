using System;
using Xunit;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.SensitiveData.Tests
{
    public class FieldCryptoEngineStringMembersTests
    {

        readonly FieldCryptoEngine _engine;

        public FieldCryptoEngineStringMembersTests()
        {
            var keyGenerator = new RsaKeyGenerator();
            var keyStore = new InMemoryRsaKeyStore(keyGenerator);
            var provider = new RsaEncryptionProvider(keyStore);
            _engine = new FieldCryptoEngine(provider);
        }


        [Fact]
        public void Encrypt_should_encrypt_private_string_field_with_sensitivedata_attribute()
        {
            var person = new Person("John", "Doe");
            var userId = Guid.NewGuid().ToString();

            _engine.Encrypt(userId, person);

            // Private Field of type String
            Assert.NotEqual("Doe", person.SurName);

            _engine.Decrypt(userId, person);

            Assert.Equal("Doe", person.SurName);
        }

        [Fact]
        public void Encrypt_should_encrypt_public_string_field_with_sensitivedata_attribute()
        {
            var person = new Person("John", "Doe");
            var userId = Guid.NewGuid().ToString();

            _engine.Encrypt(userId, person);

            // Private Field of type String
            Assert.NotEqual("John", person.firstName);

            _engine.Decrypt(userId, person);

            Assert.Equal("John", person.firstName);
        }

        [Fact]
        public void Encrypt_should_encrypt_public_string_property_with_sensitivedata_attribute()
        {
            var person = new Person("John", "Doe") { SocialSecurityNumber = "123qwe" };
            var userId = Guid.NewGuid().ToString();

            _engine.Encrypt(userId, person);

            // Public Property of type String
            Assert.NotEqual("123qwe", person.SocialSecurityNumber);

            _engine.Decrypt(userId, person);

            Assert.Equal("123qwe", person.SocialSecurityNumber);
        }

        [Fact]
        public void Encrypt_should_encrypt_private_string_property_with_sensitivedata_attribute()
        {
            var person = new Person("John", "Doe", "aliens");
            var userId = Guid.NewGuid().ToString();

            _engine.Encrypt(userId, person);

            // Public Property of type String
            Assert.NotEqual("aliens", person.SexualPreferencesProxy);

            _engine.Decrypt(userId, person);

            Assert.Equal("aliens", person.SexualPreferencesProxy);
        }




        public class Person
        {
            [SensitiveData]
            public string firstName;

            [SensitiveData]
            string surName;
            public string SurName => surName;

            [SensitiveData]
            public string SocialSecurityNumber { get; set; }

            [SensitiveData]
            string SexualPreferences { get; set; }

            public string SexualPreferencesProxy { get { return SexualPreferences; } }

            public Person(string firstName, string surName, string sexualPreferences = "none of your business")
            {
                this.firstName = firstName;
                this.surName = surName;
                this.SexualPreferences = sexualPreferences;
            }
        }
    }

    
}
