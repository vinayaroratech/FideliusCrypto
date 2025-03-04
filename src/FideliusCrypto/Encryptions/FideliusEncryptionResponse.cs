namespace FideliusCrypto;

public record FideliusEncryptionResponse(
    string EncryptedData,
    string Iv,
    string Salt);
