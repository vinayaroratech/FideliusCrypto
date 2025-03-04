using FideliusCrypto.Encryptions;
using FideliusCrypto.KeyPairGen;

namespace FideliusCrypto.Tests;

public class FideliusEncryptionServiceTests
{
    private readonly FideliusEncryptionService _encryptionService;

    public FideliusEncryptionServiceTests()
    {
        _encryptionService = new FideliusEncryptionService();
    }

    [Fact]
    public void Encrypt_ShouldReturnValidResponse()
    {
        // Arrange
        var senderPub = "BAXAIx7aWOqR36CRiRe2h/iWUVn4qNqiel/1rInWt8Uga4jSBUOGnE2Q9DkwfEoUp8C6I9K6kmtn57E5nC95o04=";
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
}
