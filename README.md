# GDPR-FieldCryptoEngine
An encryption engine written for NET Core and NET Framework for all kind of purposes. 

The main goal starting this project is to create a **plug-and-play** solution in order to **encrypt** and **decrypt** Class Members (Fields & Properties).

The solution has been build with abstraction in mind, so you can implement your own classes or use the existing ones.
The solution also uses Inversion Of Control (IoC) Design Principals. Choose your preferred IoC Container (E.g. Autofac) in order to register the desired classes.

## GDPR ARTICLE 25 & 17
Two reasons why this solution may be usefull to you:

1. You want to implement GDPR article 25 Privacy By Default. You want an easy solution that supports encryption and decryption of Class Member Data.
2. You want to implement GDPR article 17 (right to erasure or "right to be forgotten)", in order to (hard) delete data related to an individual. The idea is that personal related data is stored encrypted and every individual has its own personal encryption key. When you throw away the key, the data can never be decrypted.

## Feature List
- [x] Engine: Support encrypt/decrypt for both primitive types and refence types.
- [x] Engine: Non String types can be serialized into another Field or Property in order to encrypt/decrypt.
- [x] Provider: RSA Encryption Provider
- [ ] Provider: AES Encryption Provider
- [x] Key store: File system storage support for RSA keys.
- [x] Key store: Inmemmory support for RSA keys.
- [ ] Key store: Protected Cache as concrete IKeyStore Implementation and functioning as Proxy.


## Dependencies
- MessagePack (Binary Serialization)
- Microsoft.CSHarp (support for Dynamics)
- Portable.BouncyCastle (light weight Encryption library)


## Example




