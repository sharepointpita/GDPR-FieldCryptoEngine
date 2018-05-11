using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Yunify.Security.Encryption.Asymmentric.RSA
{
    public class RsaKeyGenerator : IRsaKeyGenerator
    {
        /// <summary>
        /// Generate a RSA key with a defined size in bits
        /// </summary>
        /// <param name="keySizeInBits">Size in bits</param>
        /// <returns>Key Pair containing Public and Private key</returns>
        public AsymmetricCipherKeyPair GenerateRsaKey(RsaKeySize keySizeInBits)
        {
            var r = new RsaKeyPairGenerator();

            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();

            r.Init(new KeyGenerationParameters(new SecureRandom(randomGenerator), (int)keySizeInBits));

            var keys = r.GenerateKeyPair();

            return keys;
        }

        /// <summary>
        /// Generate a public key based on the private key modules and exponent
        /// </summary>
        /// <param name="modulus"></param>
        /// <param name="exponent"></param>
        /// <returns></returns>
        public AsymmetricKeyParameter GeneratePublicKey(BigInteger modulus, BigInteger exponent)
        {
            return new RsaKeyParameters(false, modulus, exponent);
        }

    }
}
