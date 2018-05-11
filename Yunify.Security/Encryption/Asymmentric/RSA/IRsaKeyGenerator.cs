using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace Yunify.Security.Encryption.Asymmentric.RSA
{
    public interface IRsaKeyGenerator
    {
        AsymmetricCipherKeyPair GenerateRsaKey(RsaKeySize keySizeInBits);

        AsymmetricKeyParameter GeneratePublicKey(BigInteger modulus, BigInteger exponent);
    }
}
