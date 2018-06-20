namespace Yunify.Security.Encryption.Symmetric.AES
{
    /// <summary>
    /// AES key size in bits
    /// </summary>
    /// <seealso cref="https://en.wikipedia.org/wiki/Key_size"/>
    public enum AesKeySize
    {
        /// <summary>
        /// Sufficient to protect classified information up to the SECRET level
        /// </summary>
        A128 = 128,

        /// <summary>
        /// Sufficient to protect classified information up to the SECRET level
        /// </summary>
        A192 = 192,

        /// <summary>
        /// Sufficient to protect classified information up to the TOP SECRET level
        /// </summary>
        A256 = 256
    }
}
