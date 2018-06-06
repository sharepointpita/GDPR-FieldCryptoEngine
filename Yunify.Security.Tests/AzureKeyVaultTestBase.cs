using Microsoft.Extensions.Configuration;
using System.IO;
using Yunify.Security.Tests.Secrets;

namespace Yunify.Security.Tests
{
    public abstract class AzureKeyVaultTestBase
    {
        public IConfigurationRoot Configuration { get; set; }

        public AzureKeyVaultSecrets AzureKeyVaultSecrets {  get; private set; }

        public AzureKeyVaultTestBase()
        {
            // Retrieve appsettings And create IConfigurationRoot object
            BuildConfiguration();

            // Get configuration settings
            AzureKeyVaultSecrets = new AzureKeyVaultSecrets();
            AzureKeyVaultSecrets.VaultAddress = Configuration.GetValue<string>("azureKeyVaultSecrets:vaultAddress");
            AzureKeyVaultSecrets.ClientId = Configuration.GetValue<string>("azureKeyVaultSecrets:clientId");
            AzureKeyVaultSecrets.ClientSecret = Configuration.GetValue<string>("azureKeyVaultSecrets:clientSecret");
        }

        void BuildConfiguration()
        {
            // Build configuration
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddUserSecrets<AzureKeyVaultSecrets>();

            Configuration = builder.Build();
        }

    }
}
