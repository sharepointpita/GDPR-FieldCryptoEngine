using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Yunify.Security.Encryption.Asymmentric.RSA;

namespace Yunify.Security.Encryption.KeyStore
{
    public class FileSystemRsaKeyStore : IKeyStore<AsymmetricCipherKeyPair>
    {
        readonly IRsaKeyGenerator _keyGenerator;

        readonly string _pkcs8Password = "123qwe";
        readonly string _storeDirectoryPath = Environment.CurrentDirectory + "\\keys";

        

        public FileSystemRsaKeyStore(IRsaKeyGenerator keyGenerator)
        {
            _keyGenerator = keyGenerator;

            if (!Directory.Exists(_storeDirectoryPath))
            {
                Directory.CreateDirectory(_storeDirectoryPath);
            }
        }


        public void DeleteKeyAsync(string keyId)
        {
            File.Delete(GetFilePath(keyId));
        }


        public AsymmetricCipherKeyPair CreateKeyAsync(string keyId)
        {

            /*
            * Create new RSA key
            */
            var key = _keyGenerator.GenerateRsaKey(RsaKeySize.R3072);


            /*
             * Store Private Key
            */

            // create pem file (PKCS#8 --> Private-Key Information Syntax Standard)
            StringWriter sw = new StringWriter();

            PemWriter pWrt = new PemWriter(sw);
            Pkcs8Generator pkcs8 = new Pkcs8Generator(key.Private, Pkcs8Generator.PbeSha1_3DES);
            pkcs8.Password = _pkcs8Password.ToCharArray();

            pWrt.WriteObject(pkcs8);
            pWrt.Writer.Close();

            // Store private key
            File.WriteAllText(GetFilePath(keyId), sw.ToString());

            return key;
        }

        public AsymmetricCipherKeyPair GetKeyAsync(string keyId)
        {
            try
            {
                var result = File.ReadAllText(GetFilePath(keyId));

                PemReader pRd = new PemReader(new StringReader(result), new Password(_pkcs8Password.ToCharArray()));

                AsymmetricKeyParameter rdKey = (AsymmetricKeyParameter)pRd.ReadObject();
                pRd.Reader.Close();

                // create public key given the private key Module and Exponent
                var privateKeyParameters = (RsaPrivateCrtKeyParameters)rdKey;

                return new AsymmetricCipherKeyPair( _keyGenerator.GeneratePublicKey(privateKeyParameters.Modulus, privateKeyParameters.PublicExponent), rdKey);
            }
            catch (FileNotFoundException)
            {
                return null;
            }
        }

        private string GetFilePath(string keyId)
        {
            return Environment.CurrentDirectory + $"\\private_key_{keyId}.pem";
        }


        private class Password
            : IPasswordFinder
        {
            private readonly char[] password;

            public Password(
                char[] word)
            {
                this.password = (char[])word.Clone();
            }

            public char[] GetPassword()
            {
                return (char[])password.Clone();
            }
        }

    }
}
