using System;

namespace Yunify.Security
{

    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property)]
    public class SensitiveDataAttribute : Attribute
    {
        private string _serializeToMember;

        // Define Reviewed property.
        // This is a read/write attribute.

        public virtual string SerializeToMember
        {
            get { return _serializeToMember; }
            set { _serializeToMember = value; }
        }

    }
}
