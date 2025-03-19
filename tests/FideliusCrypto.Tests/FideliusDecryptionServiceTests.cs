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
    public void Decrypt_UsingAlicePrivateKey_ValidRequest_ReturnsDecryptedData()
    {
        // Arrange
        var decryptionRequest = new FideliusDecryptionRequest(
            KeyStorageUtil.Alice.PrivateKey,
            KeyStorageUtil.Alice.Nonce,
            KeyStorageUtil.Bob.PublicKey,
            KeyStorageUtil.Bob.Nonce,
            "8ocpmI6RIVAjsgjlj82W5b1MXBHidTc8oYeq0HkxdC0vEGeMPxSULKIerI6DNPPxEYpc");

        // Act
        var response = _decryptionService.Decrypt(decryptionRequest);

        // Assert
        Assert.NotNull(response);
        Assert.IsType<FideliusDecryptionResponse>(response);
        Assert.NotEmpty(response.DecryptedData);
        Assert.Equal("EncryptUsingBobPrivateKeyTestString", response.DecryptedData);
    }

    [Fact]
    public void Decrypt_UsingBobPrivateKey_ValidRequest_ReturnsDecryptedData()
    {
        // Arrange
        var decryptionRequest = new FideliusDecryptionRequest(
            KeyStorageUtil.Bob.PrivateKey,
            KeyStorageUtil.Bob.Nonce,
            KeyStorageUtil.Alice.PublicKey,
            KeyStorageUtil.Alice.Nonce,
            "w4w5nqSVJ2w+vIN5H2hfiQwr+1mCCtLKg3A=");

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
        var request = new FideliusDecryptionRequest(
            "encryptedData",
            "nonce",
            "nonce",
            "invalid_key",
            "validPublicKey");
        Assert.Throws<DecryptionException>(() => _decryptionService.Decrypt(request));
    }

    [Fact]
    public void Decrypt_InvalidPublicKey_ThrowsDecryptionException()
    {
        var request = new FideliusDecryptionRequest(
            "encryptedData",
            "nonce",
            "nonce",
            "validPrivateKey",
            "invalid_key");
        Assert.Throws<DecryptionException>(() => _decryptionService.Decrypt(request));
    }
}
