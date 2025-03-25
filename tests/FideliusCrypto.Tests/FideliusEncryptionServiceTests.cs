using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;

namespace FideliusCrypto.Tests;

public class FideliusEncryptionServiceTests
{
    private readonly Mock<ILogger<FideliusEncryptionService>> _loggerMock;
    private readonly FideliusEncryptionService _encryptionService;

    public FideliusEncryptionServiceTests()
    {
        _loggerMock = new Mock<ILogger<FideliusEncryptionService>>();
        _encryptionService = new FideliusEncryptionService(_loggerMock.Object);
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
            string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);

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

    [Fact]
    public void Encrypt_InvalidPrivateKeyLength_ThrowsEncryptionException()
    {
        // Arrange
        var encryptionRequest = new FideliusEncryptionRequest(
            "G8N7RLM9zTXxTLj2P/yokWaEmeHtmmwruUHlXiNlGQ==",
            KeyStorageUtil.Bob.Nonce,
            KeyStorageUtil.Alice.PublicKey,
            KeyStorageUtil.Alice.Nonce,
            "EncryptUsingBobPrivateKeyTestString");

        // Act -> Assert
        var response = _encryptionService.Encrypt(encryptionRequest);
        _loggerMock.VerifyLog(LogLevel.Warning, "Invalid private key length. Expected 32 bytes but passed 31.", Times.Once());
    }
}
