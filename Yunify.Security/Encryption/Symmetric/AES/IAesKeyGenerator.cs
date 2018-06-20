namespace Yunify.Security.Encryption.Symmetric.AES
{
    public interface IAesKeyGenerator
    {
        AesKey GenerateAesKey(AesKeySize keySizeInBits);
    }
}
