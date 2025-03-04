using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace FideliusCrypto.Decryptions;

public interface IFideliusDecryptionService
{
    FideliusDecryptionResponse Decrypt(FideliusDecryptionRequest decryptionRequest);
}

public class FideliusDecryptionService : IFideliusDecryptionService
{
    public FideliusDecryptionResponse Decrypt(FideliusDecryptionRequest decryptionRequest)
    {
        byte[] xorOfNonces = FideliusUtils.CalculateXorOfBytes(
            Convert.FromBase64String(decryptionRequest.SenderNonce),
            Convert.FromBase64String(decryptionRequest.RequesterNonce)
        );

        byte[] iv = xorOfNonces.Skip(xorOfNonces.Length - 12).ToArray();
        byte[] salt = xorOfNonces.Take(20).ToArray();

        string decryptedData = Decrypt(
            iv,
            salt,
            decryptionRequest.RequesterPrivateKey,
            decryptionRequest.SenderPublicKey,
            decryptionRequest.EncryptedData
        );

        return new FideliusDecryptionResponse(decryptedData);
    }

    private static string Decrypt(byte[] iv, byte[] salt, string requesterPrivateKey, string senderPublicKey, string encryptedDataAsBase64Str)
    {
        string sharedSecret = FideliusUtils.ComputeSharedSecret(requesterPrivateKey, senderPublicKey);

        byte[] aesEncryptionKey = FideliusUtils.Sha256Hkdf(salt, sharedSecret, 32);

        string decryptedData = "";
        try
        {
            byte[] encryptedBytes = Convert.FromBase64String(encryptedDataAsBase64Str);

            GcmBlockCipher cipher = new(new AesEngine());
            AeadParameters parameters = new(
                new KeyParameter(aesEncryptionKey),
                128,
                iv,
                null
            );

            cipher.Init(false, parameters);
            byte[] cipherBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
            int encryptedBytesLength = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, cipherBytes, 0);
            cipher.DoFinal(cipherBytes, encryptedBytesLength);

            decryptedData = System.Text.Encoding.UTF8.GetString(cipherBytes);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }

        return decryptedData;
    }
}
