namespace Yunify.Security.Encryption.Symmetric.AES
{
    public class AesKey
    {
        /// <summary>
        /// The actual Key
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// The Initial Vector
        /// </summary>
        public string IV { get; set; }
    }
}
