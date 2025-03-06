using Microsoft.Extensions.DependencyInjection;

namespace FideliusCrypto.Tests;

public class FideliusEncryptionServiceTests
{
    private readonly IFideliusEncryptionService _encryptionService;
    public FideliusEncryptionServiceTests()
    {
        var services = new ServiceCollection();
        services.AddLogging()
            .AddSingleton<IFideliusEncryptionService, FideliusEncryptionService>();
        var serviceProvider = services.BuildServiceProvider();
        _encryptionService = serviceProvider.GetRequiredService<IFideliusEncryptionService>();
    }

    [Fact]
    public void Encrypt_UsingAlicePrivateKey_ShouldReturnValidResponse()
    {
        // Arrange
        var encryptionRequest = new FideliusEncryptionRequest(
            KeyStorageUtil.Alice.PrivateKey,
            KeyStorageUtil.Alice.Nonce,
            KeyStorageUtil.Bob.PublicKey,
            KeyStorageUtil.Bob.Nonce,
            "testString");

        // Act
        var response = _encryptionService.Encrypt(encryptionRequest);

        // Assert
        Assert.NotNull(response);
        Assert.False(string.IsNullOrEmpty(response.EncryptedData));
        Assert.False(string.IsNullOrEmpty(response.Iv));
        Assert.False(string.IsNullOrEmpty(response.Salt));
    }
    
    [Fact]
    public void Encrypt_UsingBobPrivateKey_ShouldReturnValidResponse()
    {
        // Arrange
        var encryptionRequest = new FideliusEncryptionRequest(
            KeyStorageUtil.Bob.PrivateKey,
            KeyStorageUtil.Bob.Nonce,
            KeyStorageUtil.Alice.PublicKey,
            KeyStorageUtil.Alice.Nonce,
            "EncryptUsingBobPrivateKeyTestString");

        // Act
        var response = _encryptionService.Encrypt(encryptionRequest);

        // Assert
        Assert.NotNull(response);
        Assert.False(string.IsNullOrEmpty(response.EncryptedData));
        Assert.False(string.IsNullOrEmpty(response.Iv));
        Assert.False(string.IsNullOrEmpty(response.Salt));
    }

    [Fact]
    public void Encrypt_ShouldHandleException()
    {
        // Arrange
        var encryptionRequest = new FideliusEncryptionRequest(
            null, null, null, null, null);

        // Act & Assert
        var exception = Record.Exception(() => _encryptionService.Encrypt(encryptionRequest));
        Assert.NotNull(exception);
    }

    [Fact]
    public void Encrypt_InvalidPrivateKey_ThrowsEncryptionException()
    {
        var request = new FideliusEncryptionRequest("invalid_key", "nonce", "validPublicKey", "nonce", "test");
        Assert.Throws<EncryptionException>(() => _encryptionService.Encrypt(request));
    }

    [Fact]
    public void Encrypt_InvalidPublicKey_ThrowsEncryptionException()
    {
        var request = new FideliusEncryptionRequest("validPrivateKey", "nonce", "invalid_key", "nonce", "test");
        Assert.Throws<EncryptionException>(() => _encryptionService.Encrypt(request));
    }
}
