namespace FideliusCrypto;

public class EncryptionException : FideliusCryptoException
{
    public EncryptionException(string message) : base(message) { }
    public EncryptionException(string message, Exception innerException) : base(message, innerException) { }
}
