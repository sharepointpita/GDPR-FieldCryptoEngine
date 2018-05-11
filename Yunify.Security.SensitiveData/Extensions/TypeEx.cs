using System;

namespace Yunify.Security.SensitiveData
{
    internal static class TypeEx
    {
        public static object GetDefault(this Type type)
        {
            if (type.IsValueType)
            {
                return Activator.CreateInstance(type);
            }
            return null;
        }
    }
}
