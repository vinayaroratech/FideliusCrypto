namespace FideliusCrypto.Decryptions;

public record FideliusDecryptionRequest(
    string EncryptedData,
    string RequesterNonce,
    string SenderNonce,
    string RequesterPrivateKey,
    string SenderPublicKey);
