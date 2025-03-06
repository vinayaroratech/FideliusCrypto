namespace FideliusCrypto;

public record FideliusDecryptionRequest(
    string RequesterPrivateKey,
    string RequesterNonce,
    string SenderPublicKey,
    string SenderNonce,
    string EncryptedData);
