using Microsoft.Extensions.DependencyInjection;

namespace FideliusCrypto.Tests;

public class FideliusKeyPairGenerationTests
{
    private readonly IFideliusKeyPairGeneration _keyPairGen;
    public FideliusKeyPairGenerationTests()
    {
        var services = new ServiceCollection();
        services.AddLogging()
            .AddSingleton<IFideliusKeyPairGeneration, FideliusKeyPairGeneration>();
        var serviceProvider = services.BuildServiceProvider();
        _keyPairGen = serviceProvider.GetRequiredService<IFideliusKeyPairGeneration>();
    }

    [Fact]
    public void Generate_ShouldReturnFideliusKeyMaterial()
    {
        // Arrange

        // Act
        var result = _keyPairGen.Generate();

        // Assert
        Assert.NotNull(result);
        Assert.False(string.IsNullOrEmpty(result.PrivateKey));
        Assert.False(string.IsNullOrEmpty(result.PublicKey));
        Assert.False(string.IsNullOrEmpty(result.X509PublicKey));
        Assert.False(string.IsNullOrEmpty(result.Nonce));
    }
}