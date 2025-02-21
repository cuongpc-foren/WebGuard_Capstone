//using NET_SECURITY_MODEL.ConfigurationModel;
//using StackExchange.Redis;

//namespace NET_GRPC_SECURITY.Installers
//{
//    public class Installer : IInstaller
//    {
//        public void InstallService(IServiceCollection services, IConfiguration configuration)
//        {
//            var appConfiguration = new AppConfiguration();
//            configuration.GetSection("AppConfiguration").Bind(appConfiguration);

//            services.AddSingleton(appConfiguration);
//        }
//    }
//}
