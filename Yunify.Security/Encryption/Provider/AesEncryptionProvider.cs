using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Symmetric;

namespace Yunify.Security.Encryption.Provider
{
    public class AesEncryptionProvider : IEncryptionProvider
    {
        private readonly IKeyStore<AesKey> _keyStore;

        public AesEncryptionProvider(IKeyStore<AesKey> keyStore)
        {
            _keyStore = keyStore;
        }


        public async Task<string> EncryptAsync(string userId, byte[] bytesToEncrypt)
        {
            AesKey aesKey = await _keyStore.GetKeyAsync(userId) ?? await _keyStore.CreateKeyAsync(userId);

            Byte[] bkey = Encoding.UTF8.GetBytes(aesKey.Key);
            Byte[] bIV = Encoding.UTF8.GetBytes(aesKey.IV);

            Byte[] encryptData = null; // encrypted data

            using (Aes Aes = Aes.Create())
            {
                using (MemoryStream Memory = new MemoryStream())
                {
                    using (CryptoStream Encryptor = new CryptoStream(Memory,Aes.CreateEncryptor(bkey, bIV), CryptoStreamMode.Write))
                    {
                        Encryptor.Write(bytesToEncrypt, 0, bytesToEncrypt.Length);
                        Encryptor.FlushFinalBlock();
                        encryptData = Memory.ToArray();
                    }
                }

                string base64Enc = Convert.ToBase64String(encryptData);
                return base64Enc;
            }
        }

        public async Task<byte[]> DecryptAsync(string userId, string txtToDecryptBase64Enc)
        {
            AesKey aesKey = await _keyStore.GetKeyAsync(userId) ?? await _keyStore.CreateKeyAsync(userId);

            Byte[] bKey = Encoding.UTF8.GetBytes(aesKey.Key);
            Byte[] bIV = Encoding.UTF8.GetBytes(aesKey.IV);

            Byte[] encryptedData = Convert.FromBase64String(txtToDecryptBase64Enc);

            using (Aes Aes = Aes.Create())
            {
                using (MemoryStream Memory = new MemoryStream(encryptedData))
                {
                    using (CryptoStream Decryptor = new CryptoStream(Memory, Aes.CreateDecryptor(bKey, bIV), CryptoStreamMode.Read))
                    {
                        using (MemoryStream tempMemory = new MemoryStream())
                        {
                            Byte[] Buffer = new Byte[1024];
                            Int32 readBytes = 0;
                            while ((readBytes = Decryptor.Read(Buffer, 0, Buffer.Length)) > 0)
                            {
                                tempMemory.Write(Buffer, 0, readBytes);
                            }

                            return tempMemory.ToArray();
                        }
                    }
                }
            }
        }

    }
}
