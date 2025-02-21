namespace NET_GRPC_SECURITY.Installers
{
    public static class InstallerExtensions
    {
        public static void InstallerServicesInAssembly(this IServiceCollection services, IConfiguration configuration)
        {
            var installer = typeof(Program).Assembly.ExportedTypes.Where(p => typeof(IInstaller).IsAssignableFrom(p) && !p.IsInterface && !p.IsAbstract)
                .Select(Activator.CreateInstance).Cast<IInstaller>().ToList();

            installer.ForEach(installers => installers.InstallService(services, configuration));
        }
    }
}
