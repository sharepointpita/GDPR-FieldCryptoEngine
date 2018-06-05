using Yunify.Security;

namespace Console.Models
{
    public class Person
    {
        [SensitiveData]
        public string firstName;

        [SensitiveData]
        string surName;
        public string SurName => surName;

        [SensitiveData]
        public string SocialSecurityNumber { get; set; }

        [SensitiveData]
        string SexualPreferences { get; set; }

        public string SexualPreferencesProxy { get { return SexualPreferences; } }

        public Person(string firstName, string surName, string sexualPreferences = "none of your business")
        {
            this.firstName = firstName;
            this.surName = surName;
            this.SexualPreferences = sexualPreferences;
        }
    }
}
