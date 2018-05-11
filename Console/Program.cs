using Autofac;
using Org.BouncyCastle.Crypto;
using System;
using Yunify.Security;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;
using Yunify.Security.SensitiveData;

namespace EncryptionEngineConsole
{
    class Program
    {
        static IContainer _IoCContainer;

        static void Main(string[] args)
        {
            InitIoCContainer();

            Example1();
        }

        private static void Example1()
        {
            throw new NotImplementedException();
        }

        static void InitIoCContainer()
        {
            //  Autofac as IoC container

            ContainerBuilder builder = new ContainerBuilder();

            // Register individual components

            // --> Key Generator
            builder.RegisterType<RsaKeyGenerator>()
               .As<IRsaKeyGenerator>();

            // --> Key Store
            builder.RegisterType<InMemoryRsaKeyStore>()
                .As<IKeyStore<AsymmetricCipherKeyPair>>();

            // --> Encryption Provider
            builder.RegisterType<RsaEncryptionProvider>()
               .As<IEncryptionProvider>();

            // --> Engine
            builder.RegisterType<FieldCryptoEngine>()
                .AsSelf();

            _IoCContainer = builder.Build();
        }
    }
}
