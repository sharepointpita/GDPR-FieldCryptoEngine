using System;

namespace Yunify.Security
{

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property)]
    public class SensitiveDataKeyIdAttribute : Attribute
    {
    }
}
