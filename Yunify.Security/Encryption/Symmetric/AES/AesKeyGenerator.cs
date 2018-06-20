using System;
using System.Text;

namespace Yunify.Security.Encryption.Symmetric.AES
{
    public class AesKeyGenerator : IAesKeyGenerator
    {
        //Function to get random number
        private static readonly Random getrandom = new Random();

        public static int GetRandomNumber(int min, int max)
        {
            lock (getrandom) // synchronize
            {
                return getrandom.Next(min, max);
            }
        }


        /// <summary>
        /// Generate a random key
        /// </summary>
        /// <param name="length">Key length in bytes</param>
        /// <returns>return random value</returns>
        private string GetRandomStr(int length)
        {
            char[] arrChar = new char[]{
           'a','b','d','c','e','f','g','h','i','j','k','l','m','n','p','r','q','s','t','u','v','w','z','y','x',
           '0','1','2','3','4','5','6','7','8','9',
           'A','B','C','D','E','F','G','H','I','J','K','L','M','N','Q','P','R','T','S','V','U','W','X','Y','Z'
          };

            StringBuilder num = new StringBuilder();

            for (int i = 0; i < length; i++)
            {
                num.Append(arrChar[GetRandomNumber(0, arrChar.Length)].ToString());
            }

            return num.ToString();
        }

        

        public AesKey GenerateAesKey(AesKeySize keySizeInBits)
        {
            return new AesKey()
            {
                Key = GetRandomStr((int)keySizeInBits / 8), //xx bytes = xx * 8 bit
                IV =  GetRandomStr(16)                       //16 bytes = 128bit
            };
        }
    }
}
