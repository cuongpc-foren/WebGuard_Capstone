namespace NET_GRPC_SECURITY.Installers
{
    public interface IInstaller
    {
        void InstallService(Microsoft.Extensions.DependencyInjection.IServiceCollection services, Microsoft.Extensions.Configuration.IConfiguration configuration);
    }
}
