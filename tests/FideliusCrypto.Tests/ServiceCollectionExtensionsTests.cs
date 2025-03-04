using Microsoft.Extensions.DependencyInjection;

namespace FideliusCrypto.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddFideliusCrypto_RegistersAllServices()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddFideliusCrypto();
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        Assert.NotNull(serviceProvider.GetService<IFideliusKeyPairGeneration>());
        Assert.NotNull(serviceProvider.GetService<IFideliusEncryptionService>());
        Assert.NotNull(serviceProvider.GetService<IFideliusDecryptionService>());
    }
}
