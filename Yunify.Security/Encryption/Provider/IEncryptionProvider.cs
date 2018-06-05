using System.Threading.Tasks;

namespace Yunify.Security.Encryption.Provider
{
    public interface IEncryptionProvider 
    {
        Task<string> EncryptAsync(string userId, byte[] bytesToEncrypt);

        Task<byte[]> DecryptAsync(string userId, string txtToDecryptBase64Enc);
    }
}