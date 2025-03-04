using FideliusCrypto.KeyPairGen;

namespace FideliusCrypto.Tests;

public class FideliusKeyPairGenerationTests
{
    [Fact]
    public void Generate_ShouldReturnFideliusKeyMaterial()
    {
        // Arrange
        var keyPairGen = new FideliusKeyPairGeneration();

        // Act
        var result = keyPairGen.Generate();

        // Assert
        Assert.NotNull(result);
        Assert.False(string.IsNullOrEmpty(result.PrivateKey));
        Assert.False(string.IsNullOrEmpty(result.PublicKey));
        Assert.False(string.IsNullOrEmpty(result.X509PublicKey));
        Assert.False(string.IsNullOrEmpty(result.Nonce));
    }
}