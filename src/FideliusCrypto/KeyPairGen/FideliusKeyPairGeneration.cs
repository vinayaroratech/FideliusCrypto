﻿using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;

namespace FideliusCrypto;

public interface IFideliusKeyPairGeneration
{
    FideliusKeyMaterial Generate();
}

public class FideliusKeyPairGeneration : IFideliusKeyPairGeneration
{
    private readonly ILogger<FideliusKeyPairGeneration> _logger;

    public FideliusKeyPairGeneration(ILogger<FideliusKeyPairGeneration> logger)
    {
        _logger = logger;
        _logger.LogInformation("FideliusKeyPairGeneration initialized.");
    }

    public FideliusKeyMaterial Generate()
    {
        try
        {
            _logger.LogInformation("Generating new ECDH key pair...");

            var keyPair = GenerateKeyPair();
            string privateKey = GetEncodedPrivateKeyAsBase64Str(keyPair.Private);
            string publicKey = GetEncodedPublicKeyAsBase64Str(keyPair.Public);
            string x509PublicKey = GetX509EncodedPublicKeyAsBase64Str(keyPair.Public);
            string nonce = GenerateBase64Nonce();

            _logger.LogInformation("Key pair generated successfully.");

            return new FideliusKeyMaterial(privateKey, publicKey, x509PublicKey, nonce);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Key pair generation failed.");
            throw new FideliusCryptoException("Failed to generate ECDH key pair.", ex);
        }
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var ecParams = CustomNamedCurves.GetByName(Constants.Curve);
        var ecSpec = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());

        var keyGen = new ECKeyPairGenerator();
        var secureRandom = new SecureRandom();
        var keyGenParam = new ECKeyGenerationParameters(ecSpec, secureRandom);
        keyGen.Init(keyGenParam);
        return keyGen.GenerateKeyPair();
    }

    private static string GetEncodedPrivateKeyAsBase64Str(AsymmetricKeyParameter privateKey)
    {
        var ecPrivateKey = (ECPrivateKeyParameters)privateKey;
        return FideliusUtils.ToBase64String(ecPrivateKey.D.ToByteArray());
    }

    private static string GetEncodedPublicKeyAsBase64Str(AsymmetricKeyParameter publicKey)
    {
        var ecPublicKey = (ECPublicKeyParameters)publicKey;
        return FideliusUtils.ToBase64String(ecPublicKey.Q.GetEncoded(false));
    }

    private static string GetX509EncodedPublicKeyAsBase64Str(AsymmetricKeyParameter publicKey)
    {
        var ecPublicKey = (ECPublicKeyParameters)publicKey;
        var x509EncodedKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ecPublicKey).GetDerEncoded();
        return FideliusUtils.ToBase64String(x509EncodedKey);
    }

    private static string GenerateBase64Nonce()
    {
        byte[] salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
        return FideliusUtils.ToBase64String(salt);
    }
}