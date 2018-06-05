using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.Tests
{
    public class AzureKeyVaultEncryptionProviderTests
    {

        private readonly IEncryptionProvider _sut;

        public AzureKeyVaultEncryptionProviderTests()
        {
            var store = new AzureKeyVaultStore("keyvaultUrl", "clientId", "clientSecret");
            _sut = new AzureKeyVaultEncryptionProvider(store);
        }


        [Fact]
        public async Task Encrypt_should_scramble_textAsync()
        {
            string userId = Guid.NewGuid().ToString();
            string text = "hello!";

            string encryptedStrBase64Enc = await _sut.EncryptAsync(userId, Encoding.UTF8.GetBytes(text));

            Assert.NotEqual(text, encryptedStrBase64Enc);
        }

        [Fact]
        public async Task Decrypt_should_revert_scrambled_text()
        {
            string userId = Guid.NewGuid().ToString();
            string text = "hello!";

            string encryptedStrBase64Enc = await _sut.EncryptAsync(userId, Encoding.UTF8.GetBytes(text));

            Assert.NotEqual(text, encryptedStrBase64Enc);

            string decryptedText = Encoding.UTF8.GetString(await _sut.DecryptAsync(userId, encryptedStrBase64Enc));

            Assert.Equal(text, decryptedText);
        }
    }
}
