using Autofac;
using System;

namespace Console
{
    class Program
    {
        static IContainer _IoCContainer;

        static void Main(string[] args)
        {
            // Example 1: FieldCryptoEngine using a RSA encryption provider with an in-memory key store.

            new FieldCryptoEngine_RsaEncryptionProvider_InMemoryRsaKeyStore_Example();

            // Example 2: FieldCryptoEngine using a RSA encryption provider with a file system key store storing PEM files.
        }

        
    }
}
