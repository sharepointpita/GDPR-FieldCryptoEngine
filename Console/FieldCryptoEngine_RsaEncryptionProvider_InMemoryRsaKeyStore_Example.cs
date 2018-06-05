using Autofac;
using Console.Models;
using Org.BouncyCastle.Crypto;
using System;
using System.Threading.Tasks;
using Yunify.Security;
using Yunify.Security.Encryption.Asymmentric.RSA;
using Yunify.Security.Encryption.KeyStore;
using Yunify.Security.Encryption.Provider;
using Yunify.Security.SensitiveData;

namespace Console
{
    public class FieldCryptoEngine_RsaEncryptionProvider_InMemoryRsaKeyStore_Example
    {
        IContainer _IoCContainer;

        public FieldCryptoEngine_RsaEncryptionProvider_InMemoryRsaKeyStore_Example()
        {
            // Step 1. Init dependencies
            InitIoCContainer();

            // step 2. Resolve engine
            var engine = _IoCContainer.Resolve<FieldCryptoEngine>();

            // Step 3. Create an Object of a Class with fields/properties containing a [SensitiveData] attribute
            //         For now we use an instance of Models.Person 
            var person = new Person("John", "Doe", "heterosexual")
            {
                SocialSecurityNumber = "AAA-GG-SSSS"
            };

            // Step 3b. Get userId. The userId will also be the key identifier. 
            string fakeUserId = "abc";

            // step 3. Encrypt an Object with SensitiveData
            Task.Run(() => engine.EncryptAsync(fakeUserId, person)).GetAwaiter().GetResult();

            // Step 4. Store the date somewhere... (E.g. MSSQL DB, Mongo, FileSystem etc.)

            // Step 5. Decrypt Object when projected back to the User
            Task.Run(() => engine.DecryptAsync(fakeUserId, person)).GetAwaiter().GetResult();
        }


        void InitIoCContainer()
        {
            //  Autofac as IoC container
            ContainerBuilder builder = new ContainerBuilder();

            ////////////////////////////////////
            // Register individual components //
            ////////////////////////////////////

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
