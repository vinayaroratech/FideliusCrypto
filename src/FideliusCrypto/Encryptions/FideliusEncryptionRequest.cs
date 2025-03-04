namespace FideliusCrypto.Encryptions;

public record FideliusEncryptionRequest(
    string SenderPrivateKey,
    string SenderNonce,
    string RequesterPublicKey,
    string RequesterNonce,
    string StringToEncrypt);
