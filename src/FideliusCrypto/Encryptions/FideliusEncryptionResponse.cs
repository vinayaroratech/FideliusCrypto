namespace FideliusCrypto.Encryptions;

public record FideliusEncryptionResponse(
    string EncryptedData,
    string Iv,
    string Salt);
