using FideliusCrypto.Decryptions;
using FideliusCrypto.KeyPairGen;

namespace FideliusCrypto.Tests;

public class FideliusDecryptionServiceTests
{
    private readonly FideliusDecryptionService _decryptionService;

    public FideliusDecryptionServiceTests()
    {
        _decryptionService = new FideliusDecryptionService();
    }

    [Fact]
    public void Decrypt_ValidRequest_ReturnsDecryptedData()
    {
        // Arrange
        var decryptionRequest = new FideliusDecryptionRequest(
            "G3UUnMPvWxCt3kE7KZ6kSpfakoeo8sn/Fzo=",
            "VjAsrITRKkdqukZ6k+4+UmVqpsJByO/TRjff+emM2zc=",
            "+BDKKmri3wzCraqzHTb9aYkobLzhdF/hYBzUoXn6WT4=",
            "C+mltA3KD+/aG52Ph9WT4u5OLaPHu/EYlc6PxA3atR0=",
            "BHC6gwMzYzisa9sl01tnSCtjzGCIGJuqgcdqnaBdsQGzIceeuXBo1lVpVRaOtiooD/SzNN9U+HDQku1cYNL5U0w=");

        // Act
        var response = _decryptionService.Decrypt(decryptionRequest);

        // Assert
        Assert.NotNull(response);
        Assert.IsType<FideliusDecryptionResponse>(response);
        Assert.NotEmpty(response.DecryptedData);
        Assert.Equal("testString", response.DecryptedData);
    }

    [Fact]
    public void Decrypt_InvalidRequest_ThrowsArgumentException()
    {
        // Arrange
        var decryptionRequest = new FideliusDecryptionRequest(
            "invalidData",
            "invalidNonce",
            "invalidNonce",
            Convert.ToBase64String(new byte[12]),
            "senderPublicKey");

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _decryptionService.Decrypt(decryptionRequest));
    }
}
