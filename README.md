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

KeyPair Generation:  
```sh
var keyPairGen = new FideliusKeyPairGeneration();
var result = keyPairGen.Generate();

Encryption:  
```sh
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

var response = _encryptionService.Encrypt(encryptionRequest);

Decryption:  
```sh
var keyPairGen = new FideliusKeyPairGeneration();
var sender = keyPairGen.Generate();
var requester = keyPairGen.Generate();

var decryptionRequest = new FideliusDecryptionRequest(
    "G3UUnMPvWxCt3kE7KZ6kSpfakoeo8sn/Fzo="
    requester.Nonce,
    sender.Nonce,
    requester.PrivateKey,
    sender.PublicKey);

var decryptionService = new FideliusDecryptionService();

var response = decryptionService.Decrypt(decryptionRequest);