using System.Threading.Tasks;

namespace Yunify.Security.Encryption.Provider
{
    public interface IEncryptionProvider 
    {
        Task<string> EncryptAsync(string keyId, byte[] bytesToEncrypt);

        Task<byte[]> DecryptAsync(string keyId, string txtToDecryptBase64Enc);
    }
}