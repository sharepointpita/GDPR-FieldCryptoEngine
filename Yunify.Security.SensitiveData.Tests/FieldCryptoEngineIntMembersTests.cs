using System;
using Xunit;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.SensitiveData.Tests
{
    public class FieldCryptoEngineIntMembersTests
    {

        readonly FieldCryptoEngine _engine;

        public FieldCryptoEngineIntMembersTests()
        {
            var keyGenerator = new RsaKeyGenerator();
            var keyStore = new InMemoryRsaKeyStore(keyGenerator);
            var provider = new RsaEncryptionProvider(keyStore);
            _engine = new FieldCryptoEngine(provider);
        }


        [Fact]
        public void Encrypt_should_encrypt_int_field_with_sensitivedata_attribute()
        {
            int age = 40;

            var person = new Person(age);
            var userId = Guid.NewGuid().ToString();

            _engine.Encrypt(userId, person);

            Assert.NotEqual(age, person.Age);
            Assert.Equal(default(Int32), person.Age);
            Assert.NotNull(person.AgeEncrypted);

            _engine.Decrypt(userId, person);

            Assert.Equal(age, person.Age);
            Assert.Null(person.AgeEncrypted);
        }

        
        [Fact]
        public void Encrypt_should_encrypt_int_property_with_sensitivedata_attribute()
        {
            int age = 40;
            int moneyOnAccount = 25000;

            var person = new Person(age) {MoneyOnAccount = moneyOnAccount };
            var userId = Guid.NewGuid().ToString();

            _engine.Encrypt(userId, person);

            Assert.NotEqual(moneyOnAccount, person.MoneyOnAccount);
            Assert.Equal(default(Int32), person.MoneyOnAccount);
            Assert.NotNull(person.MoneyOnAccountEncrypted);

            _engine.Decrypt(userId, person);

            Assert.Equal(moneyOnAccount, person.MoneyOnAccount);
            Assert.Null(person.MoneyOnAccountEncrypted);
        }



        public class Person
        {
            [SensitiveData(SerializeToMember =nameof(AgeEncrypted))]
            int _age;
            public int Age => _age;

            public string AgeEncrypted { get; set; }


            [SensitiveData(SerializeToMember = nameof(MoneyOnAccountEncrypted))]
            public int MoneyOnAccount { get; set; }

            public string MoneyOnAccountEncrypted { get; set; }

            public Person(int age)
            {
                _age = age;
            }
        }
    }

    
}
