using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Yunify.Security.Encryption.KeyStore;

namespace Yunify.Security.Encryption.Provider
{
    public sealed class RsaEncryptionProvider : IEncryptionProvider
    {
        private readonly IKeyStore<AsymmetricCipherKeyPair> _keyStore;
        private readonly RSAEncryptionPadding _rsaEncryptionPadding = RSAEncryptionPadding.Pkcs1;

        public RsaEncryptionProvider(IKeyStore<AsymmetricCipherKeyPair> keyStore)
        {
            _keyStore = keyStore;
        }

        public async Task<string> EncryptAsync(string userId, byte[] bytesToEncrypt)
        {
            var x = await _keyStore.GetKeyAsync(userId);

            AsymmetricCipherKeyPair keys = (await _keyStore.GetKeyAsync(userId)) ?? (await _keyStore.CreateKeyAsync(userId));

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keys.Public);

            RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);

            using (RSA rsaa = RSA.Create())
            {
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Modulus = publicKey.Modulus.ToByteArrayUnsigned();
                rsaParameters.Exponent = publicKey.Exponent.ToByteArrayUnsigned();
                rsaa.ImportParameters(rsaParameters);

                byte[] enc = rsaa.Encrypt(bytesToEncrypt, _rsaEncryptionPadding);
                string base64Enc = Convert.ToBase64String(enc);
                return base64Enc;
            }
        }

        public async Task<byte[]> DecryptAsync(string userId, string txtToDecryptBase64Enc)
        {
            AsymmetricCipherKeyPair keys = await _keyStore.GetKeyAsync(userId);

            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keys.Private);

            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);

            using (RSA rsa = RSA.Create())
            {
                RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(privateKey);
                rsa.ImportParameters(rsaParameters);

                return rsa.Decrypt(Convert.FromBase64String(txtToDecryptBase64Enc), _rsaEncryptionPadding);
            }
        }

  
    }
}
