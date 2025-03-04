namespace FideliusCrypto;

public class FideliusCryptoException : Exception
{
    public FideliusCryptoException(string message) : base(message) { }
    public FideliusCryptoException(string message, Exception innerException) : base(message, innerException) { }
}
