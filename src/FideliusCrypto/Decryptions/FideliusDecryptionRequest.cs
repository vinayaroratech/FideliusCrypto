namespace FideliusCrypto;

public record FideliusDecryptionRequest(
    string EncryptedData,
    string RequesterNonce,
    string SenderNonce,
    string RequesterPrivateKey,
    string SenderPublicKey);
