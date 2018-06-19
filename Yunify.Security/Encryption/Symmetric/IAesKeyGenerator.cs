namespace Yunify.Security.Encryption.Symmetric
{
    public interface IAesKeyGenerator
    {
        AesKey GenerateAesKey(AesKeySize keySizeInBits);
    }
}
