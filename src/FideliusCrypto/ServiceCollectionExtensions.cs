using Microsoft.Extensions.DependencyInjection;

namespace FideliusCrypto;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers FideliusCrypto services into .NET Dependency Injection (DI) container.
    /// </summary>
    /// <param name="services">The IServiceCollection instance.</param>
    /// <returns>The updated IServiceCollection instance.</returns>
    public static IServiceCollection AddFideliusCrypto(this IServiceCollection services)
    {
        services
            .AddSingleton<IFideliusKeyPairGeneration, FideliusKeyPairGeneration>()
            .AddSingleton<IFideliusEncryptionService, FideliusEncryptionService>()
            .AddSingleton<IFideliusDecryptionService, FideliusDecryptionService>();

        return services;
    }
}