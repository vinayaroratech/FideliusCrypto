using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace FideliusCrypto.Encryptions;

public interface IFideliusEncryptionService
{
    FideliusEncryptionResponse Encrypt(FideliusEncryptionRequest encryptionRequest);
}

public class FideliusEncryptionService : IFideliusEncryptionService
{
    public FideliusEncryptionResponse Encrypt(FideliusEncryptionRequest encryptionRequest)
    {
        byte[] xorOfNonces = FideliusUtils.CalculateXorOfBytes(
            FideliusUtils.DecodeBase64ToBytes(encryptionRequest.SenderNonce),
            FideliusUtils.DecodeBase64ToBytes(encryptionRequest.RequesterNonce)
        );

        byte[] iv = xorOfNonces.Skip(xorOfNonces.Length - 12).ToArray();
        byte[] salt = xorOfNonces.Take(20).ToArray();

        string encryptedData = Encrypt(
            iv,
            salt,
            encryptionRequest.SenderPrivateKey,
            encryptionRequest.RequesterPublicKey,
            encryptionRequest.StringToEncrypt
        );

        return new FideliusEncryptionResponse(encryptedData, Convert.ToBase64String(iv), Convert.ToBase64String(salt));
    }

    private static string Encrypt(byte[] iv, byte[] salt, string senderPrivateKey, string requesterPublicKey, string stringToEncrypt)
    {
        string sharedSecret = FideliusUtils.ComputeSharedSecret(senderPrivateKey, requesterPublicKey);

        byte[] aesEncryptionKey = FideliusUtils.Sha256Hkdf(salt, sharedSecret, 32);

        string encryptedData = "";
        byte[] stringBytes = System.Text.Encoding.UTF8.GetBytes(stringToEncrypt);

        GcmBlockCipher cipher = new(new AesEngine());
        AeadParameters parameters = new(
            new KeyParameter(aesEncryptionKey),
            128,
            iv,
            null
        );

        cipher.Init(true, parameters);
        byte[] cipherBytes = new byte[cipher.GetOutputSize(stringBytes.Length)];
        int encryptedBytesLength = cipher.ProcessBytes(stringBytes, 0, stringBytes.Length, cipherBytes, 0);
        cipher.DoFinal(cipherBytes, encryptedBytesLength);

        return FideliusUtils.EncodeBytesToBase64(cipherBytes);
    }
}
