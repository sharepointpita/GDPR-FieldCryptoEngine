using System;
using System.Text;
using Xunit;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.Tests
{
    public class RsaEncrypterProviderTests
    {

        private readonly IEncryptionProvider _provider;

        public RsaEncrypterProviderTests()
        {
            _provider = new RsaEncryptionProvider(new InMemoryRsaKeyStore(new RsaKeyGenerator()));
        }


        [Fact]
        public void Encrypt_should_scramble_text()
        {
            string userId = Guid.NewGuid().ToString();
            string text = "hello!";

            string encryptedStrBase64Enc = _provider.Encrypt(userId, Encoding.UTF8.GetBytes(text));

            Assert.NotEqual(text, encryptedStrBase64Enc);
        }

        [Fact]
        public void Decrypt_should_revert_scrambled_text()
        {
            string userId = Guid.NewGuid().ToString();
            string text = "hello!";

            string encryptedStrBase64Enc = _provider.Encrypt(userId, Encoding.UTF8.GetBytes(text));

            Assert.NotEqual(text, encryptedStrBase64Enc);

            string decryptedText = Encoding.UTF8.GetString(_provider.Decrypt(userId, encryptedStrBase64Enc));

            Assert.Equal(text, decryptedText);
        }
    }
}
