namespace Yunify.Security.Encryption.Provider
{
    public interface IEncryptionProvider 
    {
        string Encrypt(string userId, byte[] bytesToEncrypt);

        byte[] Decrypt(string userId, string txtToDecryptBase64Enc);
    }
}