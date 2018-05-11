using System;
using System.Collections.Generic;
using System.Text;

namespace Yunify.Security.Encryption.Symmetric
{
    public interface IAesKeyGenerator
    {
        string GenerateAesKey(AesKeySize keySizeInBits);
    }
}
