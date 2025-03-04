﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;

namespace FideliusCrypto;

public static class FideliusUtils
{
    public static string EncodeBytesToBase64(byte[] value)
    {
        return Convert.ToBase64String(value);
    }

    public static byte[] DecodeBase64ToBytes(string value)
    {
        return Convert.FromBase64String(value);
    }

    public static string DecodeBase64ToString(string value)
    {
        return Encoding.UTF8.GetString(Convert.FromBase64String(value));
    }

    public static byte[] CalculateXorOfBytes(byte[] byteArrayA, byte[] byteArrayB)
    {
        byte[] xorOfBytes = new byte[byteArrayA.Length];
        for (int i = 0; i < byteArrayA.Length; i++)
        {
            xorOfBytes[i] = (byte)(byteArrayA[i] ^ byteArrayB[i % byteArrayB.Length]);
        }
        return xorOfBytes;
    }

    public static byte[] Sha256Hkdf(byte[] salt, string initialKeyMaterial, int keyLengthInBytes)
    {
        HkdfBytesGenerator hkdfBytesGenerator = new(new Sha256Digest());
        HkdfParameters hkdfParameters = new(DecodeBase64ToBytes(initialKeyMaterial), salt, null);
        hkdfBytesGenerator.Init(hkdfParameters);
        byte[] encryptionKey = new byte[keyLengthInBytes];
        hkdfBytesGenerator.GenerateBytes(encryptionKey, 0, keyLengthInBytes);
        return encryptionKey;
    }

    private static ECPrivateKeyParameters GenerateECPrivateKeyFromBase64Str(string base64PrivateKey)
    {
        byte[] privateKeyBytes = DecodeBase64ToBytes(base64PrivateKey);
        var ecParams = CustomNamedCurves.GetByName(Constants.Curve);
        var ecDomainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
        var privateKeySpec = new ECPrivateKeyParameters(new Org.BouncyCastle.Math.BigInteger(privateKeyBytes), ecDomainParameters);
        return privateKeySpec;
    }

    private static ECPublicKeyParameters GenerateECPublicKeyFromBase64Str(string base64PublicKey)
    {
        byte[] publicKeyBytes = DecodeBase64ToBytes(base64PublicKey);
        var ecParams = CustomNamedCurves.GetByName(Constants.Curve);
        var ecDomainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
        var publicKeySpec = new ECPublicKeyParameters(ecParams.Curve.DecodePoint(publicKeyBytes), ecDomainParameters);
        return publicKeySpec;
    }

    private static AsymmetricKeyParameter GenerateX509PublicKeyFromBase64Str(string base64PublicKey)
    {
        byte[] publicKeyBytes = DecodeBase64ToBytes(base64PublicKey);

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(publicKeyBytes));
        return PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
    }

    public static string ComputeSharedSecret(string base64PrivateKey, string base64PublicKey)
    {
        var privateKey = GenerateECPrivateKeyFromBase64Str(base64PrivateKey);
        var publicKey = base64PublicKey.Length == 88
            ? GenerateECPublicKeyFromBase64Str(base64PublicKey)
            : GenerateX509PublicKeyFromBase64Str(base64PublicKey);

        var keyAgreement = AgreementUtilities.GetBasicAgreement("ECDH");
        keyAgreement.Init(privateKey);
        var sharedSecretBytes = keyAgreement.CalculateAgreement(publicKey).ToByteArray();
        return EncodeBytesToBase64(sharedSecretBytes);
    }

    public static string[] ReadArgsFromFile(string filepath)
    {
        List<string> argsFromFile = new();
        using StreamReader reader = new(filepath);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            argsFromFile.Add(line);
        }

        return argsFromFile.ToArray();
    }
}