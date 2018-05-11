using MessagePack;
using System;
using System.Reflection;
using System.Text;
using Yunify.Security.Encryption.Provider;

namespace Yunify.Security.SensitiveData
{
    public class FieldCryptoEngine
    {
        private readonly IEncryptionProvider _provider;

        public FieldCryptoEngine(IEncryptionProvider provider)
        {
            _provider = provider;
        }

        public virtual void Encrypt<T>(string userId, T o) where T : class
        {
            // Loop through object fields and find all fields with [SensitiveDataAttribute]
            var members = o.GetSensitiveDataMembers();
            dynamic encryptMember = null;
            dynamic val = null;
            byte[] serializedVal = null;
            Type underlyingType;
            SensitiveDataAttribute attr;

            MemberInfo srcMember;
            MemberInfo destMember;

            for (int i = 0; i < members.Length; i++)
            {
                srcMember = members[i];
                encryptMember = srcMember;
                underlyingType = srcMember.GetUnderlyingType();

                val = encryptMember.GetValue(o);

                if (val != null)
                {
                    // Check if attribute is serialized to another Member
                    attr = srcMember.GetCustomAttribute<SensitiveDataAttribute>();

                    if (!string.IsNullOrWhiteSpace(attr.SerializeToMember))
                    {
                        // 1. Get destination member
                        destMember = o.FindMemberByName(attr.SerializeToMember);

                        // 2. Validate destination member
                        ValidateDestionationMember(srcMember, destMember);

                        // 3. Set destination member as member where the encrypted value should be stored into.
                        encryptMember = (destMember as dynamic);

                        // 4. Set member value to Default constructor value
                        (srcMember as dynamic).SetValue(o, underlyingType.GetDefault());
                    }


                    // Do actual encryption to dest field
                    if (underlyingType == typeof(string))
                    {
                        encryptMember.SetValue(o, _provider.Encrypt(userId, Encoding.UTF8.GetBytes(val)));
                    }
                    else 
                    {
                        // Serialize to binary formatter with MessagePack
                        serializedVal = MessagePackSerializer.Typeless.Serialize(val);

                        encryptMember.SetValue(o, _provider.Encrypt(userId, serializedVal));
                    }

                }
            }
        }

        public virtual void Decrypt<T>(string userId, T o) where T : class
        {
            var members = o.GetSensitiveDataMembers();
            dynamic encryptMember = null;
            string val = null;
            byte[] serializedVal = null;
            Type underlyingType;
            SensitiveDataAttribute attr;

            MemberInfo srcMember;
            MemberInfo destMember;

            for (int i = 0; i < members.Length; i++)
            {
                srcMember = members[i];
                encryptMember = srcMember;
                underlyingType = srcMember.GetUnderlyingType();

                // Check if attribute is serialized to another Member
                attr = srcMember.GetCustomAttribute<SensitiveDataAttribute>();

                if (!string.IsNullOrWhiteSpace(attr.SerializeToMember))
                {
                    // 1. Get destination member
                    destMember = o.FindMemberByName(attr.SerializeToMember);

                    // 2. Validate destination member
                    ValidateDestionationMember(srcMember, destMember);

                    // 3. Set destination member as member where the encrypted value is stored into.
                    encryptMember = (destMember as dynamic);
                }

                // a. Get value out of Encrypt Member
                val = encryptMember.GetValue(o);

                if (val != null)
                {
                    // b. Clear the encrypted string
                    encryptMember.SetValue(o, null);

                    // c. Decypt and store value back into src member
                    if (underlyingType == typeof(string))
                    {
                        (srcMember as dynamic).SetValue(o, Encoding.UTF8.GetString(_provider.Decrypt(userId, val)));
                    }
                    else
                    {
                        serializedVal = _provider.Decrypt(userId, val);

                        // Deserialize to binary back to object with MessagePack
                        var obj = MessagePackSerializer.Typeless.Deserialize(serializedVal);

                        (srcMember as dynamic).SetValue(o, obj);
                    }
                }
            }
        }

        private void ValidateDestionationMember(MemberInfo sourceMember, MemberInfo destinationMember)
        {
            // 1. Check if destination member exists
            if (destinationMember == null)
            {
                throw new ArgumentException($"Member '{sourceMember.Name}' reference to another member '{destinationMember.Name}' which doesn't exists. Correct the value of Property: '{nameof(SensitiveDataAttribute.SerializeToMember)}'");
            }

            // 2. check if destination member is of type String
            if (destinationMember.GetUnderlyingType() != typeof(string))
            {
                throw new ArgumentException($"Member '{sourceMember.Name}' reference to another member '{destinationMember.Name}' which isn't of type String. Either switch type of Member or choose another Member to Serialize to");
            }
        }

    }
}
