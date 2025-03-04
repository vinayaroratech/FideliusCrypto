# FideliusCrypto 🔐  

![GitHub Workflow Status](https://github.com/vinayaroratech/FideliusCrypto/actions/workflows/dotnet-ci.yml/badge.svg)
[![NuGet](https://img.shields.io/nuget/v/FideliusCrypto.svg)](https://www.nuget.org/packages/FideliusCrypto/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/FideliusCrypto.svg)](https://www.nuget.org/packages/FideliusCrypto/)

A .NET library for secure ECDH-based encryption using **BouncyCastle**. Provides **key exchange, AES-GCM encryption, and HKDF key derivation**.

---

## 📦 **Installation**  
### **NuGet Package**
Install the package via NuGet:  
```sh
dotnet add package FideliusCrypto
```

## 🔑 **KeyPair Generation**
```sh
var keyPairGen = new FideliusKeyPairGeneration();
var result = keyPairGen.Generate();
```

## 🔒 **Encryption**
```csharp
var keyPairGen = new FideliusKeyPairGeneration();
var sender = keyPairGen.Generate();
var requester = keyPairGen.Generate();

var encryptionRequest = new FideliusEncryptionRequest(
    sender.PrivateKey,
    sender.Nonce,
    requester.PublicKey,
    requester.Nonce,
    "testString");

var encryptionService = new FideliusEncryptionService();

var response = encryptionService.Encrypt(encryptionRequest);
```
## 🔓 **Decryption**
```csharp
var keyPairGen = new FideliusKeyPairGeneration();
var sender = keyPairGen.Generate();
var requester = keyPairGen.Generate();

var decryptionRequest = new FideliusDecryptionRequest(
    "G3UUnMPvWxCt3kE7KZ6kSpfakoeo8sn/Fzo=",
    requester.Nonce,
    sender.Nonce,
    requester.PrivateKey,
    sender.PublicKey);

var decryptionService = new FideliusDecryptionService();

var response = decryptionService.Decrypt(decryptionRequest);
```
## 📝 **Usage Example**
Here's a complete example to demonstrate the usage of FideliusCrypto:

```csharp
using FideliusCrypto;

class Program
{
    static void Main(string[] args)
    {
        var keyPairGen = new FideliusKeyPairGeneration();

        // Generate key pairs for sender and requester
        var sender = keyPairGen.Generate();
        var requester = keyPairGen.Generate();

        // Create encryption request
        var encryptionRequest = new FideliusEncryptionRequest(
            sender.PrivateKey,
            sender.Nonce,
            requester.PublicKey,
            requester.Nonce,
            "This is a secret message.");

        var encryptionService = new FideliusEncryptionService();
        var encryptedResponse = encryptionService.Encrypt(encryptionRequest);

        // Display encrypted message
        Console.WriteLine("Encrypted message: " + encryptedResponse.EncryptedText);

        // Create decryption request
        var decryptionRequest = new FideliusDecryptionRequest(
            encryptedResponse.EncryptedText,
            requester.Nonce,
            sender.Nonce,
            requester.PrivateKey,
            sender.PublicKey);

        var decryptionService = new FideliusDecryptionService();
        var decryptedResponse = decryptionService.Decrypt(decryptionRequest);

        // Display decrypted message
        Console.WriteLine("Decrypted message: " + decryptedResponse.DecryptedText);
    }
}
```
## 🛠 **Features**
KeyPair Generation: Generate cryptographic key pairs for secure communication.

ECDH Key Exchange: Securely exchange keys using Elliptic Curve Diffie-Hellman (ECDH).

AES-GCM Encryption: Encrypt data with AES-GCM for authenticated encryption.

HKDF Key Derivation: Derive keys using HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

## 🔗 **Links**
GitHub Repository: [FideliusCrypto](https://github.com/vinayaroratech/FideliusCrypto)

NuGet Package: [FideliusCrypto](https://www.nuget.org/packages/FideliusCrypto/)
