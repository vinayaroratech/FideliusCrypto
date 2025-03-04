using FideliusCrypto.Decryptions;

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
            "8akXgq/VwcgFtbhtQF93vJE9udy9fv2PWOk=",
            "Gr4W05oTyjqZLjos7Rdsb/JPwrIRKDv2PYC09OJ+SXs=",
            "E/I1kBufDwzjbW7LWYeZi7j2DBB7I6nHTf5rLuU0KsY=",
            "C9ffWIcBGlr+ZwaGPpnj6A0OJJ97zv4Xp0BxCoAgwLI=",
            "BAXAIx7aWOqR36CRiRe2h/iWUVn4qNqiel/1rInWt8Uga4jSBUOGnE2Q9DkwfEoUp8C6I9K6kmtn57E5nC95o04=");

        // Act
        var response = _decryptionService.Decrypt(decryptionRequest);

        // Assert
        Assert.NotNull(response);
        Assert.IsType<FideliusDecryptionResponse>(response);
        Assert.NotEmpty(response.DecryptedData);
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
