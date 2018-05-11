namespace Yunify.Security.Encryption.Asymmentric.RSA
{
    /// <summary>
    /// RSA key size in bits
    /// </summary>
    /// <seealso cref="https://en.wikipedia.org/wiki/Key_size"/>
    public enum RsaKeySize : int
    {
        /// <summary>
        /// Used till 2030
        /// </summary>
        R2048 = 2048,

        /// <summary>
        /// User still after 2030
        /// </summary>
        R3072 = 3072,


        R4096 = 4096
    }
}
