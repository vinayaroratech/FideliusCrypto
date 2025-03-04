using Microsoft.Extensions.DependencyInjection;

namespace FideliusCrypto.Tests;

public class FideliusDecryptionServiceTests
{
    private readonly IFideliusDecryptionService _decryptionService;

    public FideliusDecryptionServiceTests()
    {
        var services = new ServiceCollection();
        services.AddLogging()
            .AddSingleton<IFideliusDecryptionService, FideliusDecryptionService>();
        var serviceProvider = services.BuildServiceProvider();
        _decryptionService = serviceProvider.GetRequiredService<IFideliusDecryptionService>();
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
        Assert.Throws<DecryptionException>(() => _decryptionService.Decrypt(decryptionRequest));
    }

    [Fact]
    public void Decrypt_InvalidPrivateKey_ThrowsDecryptionException()
    {
        var request = new FideliusDecryptionRequest("encryptedData", "nonce", "nonce", "invalid_key", "validPublicKey");
        Assert.Throws<DecryptionException>(() => _decryptionService.Decrypt(request));
    }

    [Fact]
    public void Decrypt_InvalidPublicKey_ThrowsDecryptionException()
    {
        var request = new FideliusDecryptionRequest("encryptedData", "nonce", "nonce", "validPrivateKey", "invalid_key");
        Assert.Throws<DecryptionException>(() => _decryptionService.Decrypt(request));
    }
}
