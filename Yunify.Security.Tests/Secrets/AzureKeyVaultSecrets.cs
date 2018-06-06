using System;
using System.Collections.Generic;
using System.Text;

namespace Yunify.Security.Tests.Secrets
{
    public class AzureKeyVaultSecrets
    {
        public string VaultAddress { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}
