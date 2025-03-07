using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace FideliusCrypto;

public interface IFideliusDecryptionService
{
    FideliusDecryptionResponse Decrypt(FideliusDecryptionRequest decryptionRequest);
}

public class FideliusDecryptionService : IFideliusDecryptionService
{
    private readonly ILogger<FideliusDecryptionService> _logger;

    public FideliusDecryptionService(ILogger<FideliusDecryptionService> logger)
    {
        _logger = logger;
        _logger.LogInformation("FideliusDecryptionService initialized.");

    }

    public FideliusDecryptionResponse Decrypt(FideliusDecryptionRequest decryptionRequest)
    {
        try
        {
            ValidateKeys(decryptionRequest.RequesterPrivateKey, decryptionRequest.SenderPublicKey);

            _logger.LogInformation("Starting decryption process...");

            byte[] xorOfNonces = FideliusUtils.CalculateXorOfBytes(
                FideliusUtils.FromBase64String(decryptionRequest.SenderNonce),
                FideliusUtils.FromBase64String(decryptionRequest.RequesterNonce)
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

            _logger.LogInformation("Decryption completed successfully.");

            return new FideliusDecryptionResponse(decryptedData);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Decryption failed for input: {Data}", decryptionRequest.EncryptedData);
            throw new DecryptionException("An error occurred during decryption.", ex);
        }
    }

    private string Decrypt(byte[] iv, byte[] salt, string requesterPrivateKey, string senderPublicKey, string encryptedDataAsBase64Str)
    {
        string sharedSecret = FideliusUtils.ComputeSharedSecret(requesterPrivateKey, senderPublicKey);

        byte[] aesEncryptionKey = FideliusUtils.Sha256Hkdf(salt, sharedSecret, 32);

        string decryptedData;
        try
        {
            byte[] encryptedBytes = FideliusUtils.FromBase64String(encryptedDataAsBase64Str);

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
        catch (Exception ex)
        {
            _logger.LogError(ex, "Decryption failed for input: {Data}", encryptedDataAsBase64Str);
            throw new DecryptionException("An error occurred during decryption.", ex);
        }

        return decryptedData;
    }

    private void ValidateKeys(string privateKey, string publicKey)
    {
        if (string.IsNullOrWhiteSpace(privateKey) || string.IsNullOrWhiteSpace(publicKey))
        {
            throw new DecryptionException("Private or public key cannot be empty.");
        }

        try
        {
            byte[] privateKeyBytes = FideliusUtils.FromBase64String(privateKey);
            byte[] publicKeyBytes = FideliusUtils.FromBase64String(publicKey);

            if (privateKeyBytes.Length != 32) // 256-bit private key
            {
                _logger.LogWarning("Invalid private key length. Expected 32 bytes but passed {Length}.", privateKeyBytes.Length);
                //throw new DecryptionException($"Invalid private key length. Expected 32 bytes but passed {privateKeyBytes.Length}.");
            }

            if (publicKeyBytes.Length != 65) // 520-bit uncompressed public key
            {
                _logger.LogWarning("Invalid public key length. Expected 65 bytes but passed {Length}.", publicKeyBytes.Length);
                //throw new DecryptionException($"Invalid public key length. Expected 65 bytes but passed {publicKeyBytes.Length}.");
            }
        }
        catch (FormatException)
        {
            throw new DecryptionException("Invalid Base64 encoding in private or public key.");
        }
        catch (Exception ex)
        {
            throw new DecryptionException("Invalid decryption keys.", ex);
        }
    }
}
