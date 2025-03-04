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
    public void Encrypt_ShouldReturnValidResponse()
    {
        // Arrange
        var encryptionRequest = new FideliusEncryptionRequest(
            "C9ffWIcBGlr+ZwaGPpnj6A0OJJ97zv4Xp0BxCoAgwLI=",
            "Gr4W05oTyjqZLjos7Rdsb/JPwrIRKDv2PYC09OJ+SXs=",
            "BDk3fN9IfRp4DZBWEVBfaANqKF6/44EuSnGGt9v62W3FXJK+o8gdxc0zUf2L71XZvF8Egr+vDJEyDdWmDJ3DPuM=",
             "E/I1kBufDwzjbW7LWYeZi7j2DBB7I6nHTf5rLuU0KsY=",
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
