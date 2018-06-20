# GDPR-FieldCryptoEngine
An **encryption engine** written in NET STANDARD 2.0 (thus targets both NET Core and NET Framework) which can be used for multiple purposes and aims to be cross-platform.

The main goal starting this project is to create a **plug-and-play** solution in order to **encrypt** and **decrypt** Class Members (Fields & Properties).

The solution has been build with abstraction in mind, so you can implement your own classes or use the existing ones.
The solution also uses Inversion Of Control (IoC) Design Principals. Choose your preferred IoC Container (E.g. Autofac) in order to register the desired classes.

## GDPR ARTICLE 25 & 17
Two reasons why this solution may be usefull to you:

1. You want to implement GDPR article 25 Privacy By Default. You want an easy solution that supports encryption and decryption of Class Member Data.
2. You want to implement GDPR article 17 (right to erasure or "right to be forgotten)", in order to (hard) delete data related to an individual. The idea is that personal related data is stored encrypted and every individual has its own personal key. When you throw away the key, the data can never be decrypted.

## Feature List
- [x] Engine: Support encrypt/decrypt for both **primitive types** and **refence types**.
- [x] Engine: Non String types can be **serialized** with into another Field or Property in order to encrypt/decrypt.
- [ ] Engine: Support **SensitiveDataKey** Attribute in order to retrieve the User Identifier out of the object.
- [x] Provider: **RSA Encryption** Provider
- [x] Provider: **AES Encryption** Provider
- [x] Provider: **Azure Key Vault RSA** Provider
- [x] Key store: **File system** storage support for RSA keys.
- [x] Key store: **Inmemmory support** for RSA keys.
- [x] Key store: **CacheKeyStore** as concrete IKeyStore Implementation and functioning as Proxy between EncryptionProvider and the actual KeyStore.
- [x] Key store: **Azure Key Vault**

## Dependencies
- [MessagePack (Binary Serialization)](https://msgpack.org/) 
- [Microsoft.CSHarp (support for Dynamics)](https://www.nuget.org/packages/Microsoft.CSharp/)
- [Portable.BouncyCastle (light weight Encryption library)](http://www.bouncycastle.org/csharp/)


## Example

### Person Class
```csharp
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
```

### Encrypt / Decrypt with the FieldCryptoEngine
```csharp
var person = new Person("John", "Doe", "heterosexual")
{
    SocialSecurityNumber = "AAA-GG-SSSS"
};

// The userId will also be used as the key identifier. 
string fakeUserId = "abc";

await engine.EncryptAsync(fakeUserId, person);

// After calling the EncryptAsync method the properities flagged with [SensitiveData] attribute will look scrambled:
// person.SocialSecurityNumber = 

...

engine.DecryptAsync(fakeUserId, person);
```


