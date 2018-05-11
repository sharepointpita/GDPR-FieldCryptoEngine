using System;
using System.Reflection;

namespace Yunify.Security.SensitiveData
{
    internal static class MemberInfoEx
    {
        public static Type GetUnderlyingType(this MemberInfo m)
        {
            if (m.MemberType == MemberTypes.Property)
                return (m as PropertyInfo).PropertyType;
            else if (m.MemberType == MemberTypes.Field)
                return (m as FieldInfo).FieldType;
            else
                throw new NotSupportedException("Other member types then Field and Property are not supported");
        }
    }
}
