using System;
using System.Threading.Tasks;
using Xunit;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.SensitiveData.Tests
{
    public class FieldCryptoEngineDateTimeMembersTests
    {

        readonly FieldCryptoEngine _engine;

        public FieldCryptoEngineDateTimeMembersTests()
        {
            var keyGenerator = new RsaKeyGenerator();
            var keyStore = new InMemoryRsaKeyStore(keyGenerator);
            var provider = new RsaEncryptionProvider(keyStore);
            _engine = new FieldCryptoEngine(provider);
        }

        [Fact]
        public async Task Encrypt_should_encrypt_private_datetime_field_with_sensitivedata_attribute()
        {
            var userId = Guid.NewGuid().ToString();
            var birthDate = new DateTime(1980, 1, 1);
            var person = new PersonLifeTime(birthDate);
            
            await _engine.EncryptAsync(userId, person);

            // Person BirthDate should set to a default datetime value.
            Assert.NotEqual(birthDate, person.BirthDate);
            Assert.Equal(new DateTime().ToString() , person.BirthDate.ToString());

            // Mapped field should be set with encrypted value
            Assert.NotNull(person.BirthDateEncrypted);

            // After decrypt the target member should get a Default value (this case null)
            await _engine.DecryptAsync(userId, person);
            Assert.Equal(birthDate, person.BirthDate);
            Assert.Null(person.BirthDateEncrypted);
        }

        [Fact]
        public async Task Encrypt_should_encrypt_public_datetime_field_with_sensitivedata_attribute()
        {
            var userId = Guid.NewGuid().ToString();
            var person = new PersonLifeTime(null);
            var mariageDate = new DateTime(2000, 1, 1);

            person.MariageDate = mariageDate;
            await _engine.EncryptAsync(userId, person);

            // Person MariageDate should set to a default datetime value.
            Assert.NotEqual(mariageDate, person.MariageDate);
            Assert.Equal(new DateTime().ToString(), person.MariageDate.ToString());

            // Mapped field should be set with encrypted value
            Assert.NotNull(person.MariageDateEncrypted);

            // After decrypt the target member should get a Default value (this case null)
            await _engine.DecryptAsync(userId, person);
            Assert.Equal(mariageDate, person.MariageDate);
            Assert.Null(person.MariageDateEncrypted);
        }

        [Fact]
        public async Task Encrypt_should_encrypt_public_datetime_property_with_sensitivedata_attribute()
        {
            var userId = Guid.NewGuid().ToString();
            var person = new PersonLifeTime(null);
            var graduateDate = new DateTime(2000, 1, 1);

            person.GraduateDate = graduateDate;
            await _engine.EncryptAsync(userId, person);

            // Person MariageDate should set to a default datetime value.
            Assert.NotEqual(graduateDate, person.MariageDate);
            Assert.Equal(new DateTime().ToString(), person.GraduateDate.ToString());

            // Mapped field should be set with encrypted value
            Assert.NotNull(person.GraduateDateEncrypted);

            // After decrypt the target member should get a Default value (this case null)
            await _engine.DecryptAsync(userId, person);
            Assert.Equal(graduateDate, person.GraduateDate);
            Assert.Null(person.GraduateDateEncrypted);
        }

        [Fact]
        public async Task Encrypt_should_encrypt_private_datetime_property_with_sensitivedata_attribute()
        {
            var userId = Guid.NewGuid().ToString();

            var dateOfDeath = new DateTime(2050, 1, 1);
            var person = new PersonLifeTime(null, dateOfDeath);

            await _engine.EncryptAsync(userId, person);

            // Person MariageDate should set to a default datetime value.
            Assert.NotEqual(dateOfDeath, person.DateOfDeathProxy);
            Assert.Equal(new DateTime().ToString(), person.DateOfDeathProxy.ToString());

            // Mapped field should be set with encrypted value
            Assert.NotNull(person.DateOfDeathEncrypted);

            // After decrypt the target member should get a Default value (this case null)
            await _engine.DecryptAsync(userId, person);
            Assert.Equal(dateOfDeath, person.DateOfDeathProxy);
            Assert.Null(person.DateOfDeathEncrypted);
        }




        public class PersonLifeTime
        {
            [SensitiveData(SerializeToMember = nameof(_birthDateEncrypted))]
            DateTime birthDate;
            public DateTime BirthDate => birthDate;


            string _birthDateEncrypted = null;
            public string BirthDateEncrypted => _birthDateEncrypted;


            [SensitiveData(SerializeToMember = nameof(_mariageDateEncrypted))]
            public DateTime MariageDate;
            string _mariageDateEncrypted = null;
            public string MariageDateEncrypted => _mariageDateEncrypted;



            [SensitiveData(SerializeToMember = nameof(_graduateDateEncrypted))]
            public DateTime GraduateDate { get; set; }

            string _graduateDateEncrypted = null;
            public string GraduateDateEncrypted => _graduateDateEncrypted;



            [SensitiveData(SerializeToMember = nameof(_dateOfDeathEncrypted))]
            private DateTime DateOfDeath { get; set; }

            public DateTime DateOfDeathProxy { get { return DateOfDeath; } }

            string _dateOfDeathEncrypted = null;
            public string DateOfDeathEncrypted => _dateOfDeathEncrypted;


            public PersonLifeTime(DateTime? birthDate, DateTime? dateOfDeath = null)
            {
                if (birthDate.HasValue)
                    this.birthDate = birthDate.Value;

                if (dateOfDeath.HasValue)
                    DateOfDeath = dateOfDeath.Value;
            }
        }
    }

    
}
