using System.Linq;
using System.Reflection;

namespace Yunify.Security.SensitiveData
{
    internal static class ObjectEx
    {
        private static BindingFlags _bindingFlags = BindingFlags.Instance
                                    | BindingFlags.GetProperty
                                    | BindingFlags.SetProperty
                                    | BindingFlags.GetField
                                    | BindingFlags.SetField
                                    | BindingFlags.NonPublic
                                    | BindingFlags.Public;

        public static MemberInfo[] GetSensitiveDataKeyIdMembers<T>(this T o) where T : class
        {
            return o.GetType().GetMembers(_bindingFlags)
                .Where(e => (e.MemberType == MemberTypes.Field || e.MemberType == MemberTypes.Property)
                    && e.CustomAttributes.Any(z => z.AttributeType == typeof(SensitiveDataKeyIdAttribute)))
                .ToArray();
        }   

        public static MemberInfo[] GetSensitiveDataMembers<T>(this T o) where T : class
        {
            return o.GetType().GetMembers(_bindingFlags)
                .Where(e => (e.MemberType == MemberTypes.Field || e.MemberType == MemberTypes.Property)
                    && e.CustomAttributes.Any(z => z.AttributeType == typeof(SensitiveDataAttribute)))
                .ToArray();
        }

        public static MemberInfo FindMemberByName<T>(this T o, string memberName) where T : class
        {
            // TO DO: if property then validate if has set method
            return o.GetType().GetMembers(_bindingFlags)
                .Where(e => (e.MemberType == MemberTypes.Field || e.MemberType == MemberTypes.Property)
                    && e.Name == memberName)
                .FirstOrDefault();
        }
    }
}
