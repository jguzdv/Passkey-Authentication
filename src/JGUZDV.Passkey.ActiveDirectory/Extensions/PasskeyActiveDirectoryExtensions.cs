using Microsoft.Extensions.DependencyInjection;

namespace JGUZDV.Passkey.ActiveDirectory.Extensions
{
    public static class PasskeyActiveDirectoryExtensions
    {
        public static IServiceCollection AddPasskeyActiveDirectoryServices(
            this IServiceCollection services, 
            string configSectionName) 
        {
            services.AddOptions<ActiveDirectoryOptions>()
                .BindConfiguration(configSectionName)
                .ValidateDataAnnotations()
                .ValidateOnStart();

            services.AddScoped<ActiveDirectoryService>();

            return services;
        }
    }
}
