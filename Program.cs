using ALERT.MailService;
using ALERT.NotifyService;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using DASHBOARD_DBConnection.Entities;
using DASHBOARD_DBConnection.LogEntities;
using DASHBOARD_DBConnection.UserEntities;
using IDS_SECURITY.ReconDetection;
using IDS_SECURITY.RuleBasedDetection;
using LOGGER.DosService;
using LOGGER.FileUploadService;
using LOGGER.IDSLogService;
using LOGGER.SQLIService;
using LOGGER.XSSService;
using Microsoft.EntityFrameworkCore;
using NET_GRPC_SECURITY.Security;
using NET_SECURITY_DATAACCESS.Dapper;
using WAF_SECURITY.DOSSecurity;
using WAF_SECURITY.DOSSecurity.Background;
using WAF_SECURITY.FileUploadSecurity;
using WAF_SECURITY.IPSecurity;
using WAF_SECURITY.SQLISecurity;
using WAF_SECURITY.XSSSecurity;

namespace NET_GRPC_SECURITY
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            //Add services to the container.
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                    builder.WithOrigins("http://localhost:5177")
                           .AllowAnyMethod()
                           .AllowAnyHeader()
                           .AllowCredentials())

                ;
            });
            builder.Services.AddSignalR();
            //Add services to the container.
            builder.Services.AddDbContext<NetsecurityContext>(option => option.UseSqlite(builder.Configuration.GetConnectionString("SqlConnection")));
            builder.Services.AddGrpc().AddJsonTranscoding();
            //Add cache memory
            builder.Services.AddMemoryCache();
            //Custom TokenBucket
            builder.Services.AddSingleton<ITokenBucketService, TokenBucketService>();
            builder.Services.AddHostedService<TokenBucketUpdater>();

            builder.Host.UseServiceProviderFactory(new AutofacServiceProviderFactory());

            //Call ConfigureContainer on the Host sub property 
            builder.Host.ConfigureContainer<ContainerBuilder>(builder =>
            {
                //CONTEXT
                builder.RegisterType<NetsecurityContext>().AsSelf();
                builder.RegisterType<LogContext>().AsSelf();
                builder.RegisterType<UserContext>().AsSelf();
                builder.RegisterType<DapperContext>().As<IDapperContext>();
                //WAF
                builder.RegisterType<SQLITesting>().As<ISQLITesting>();
                builder.RegisterType<XSSTesting>().As<IXSSTesting>();
                builder.RegisterType<FileUploadTesting>().As<IFileUploadTesting>();
                builder.RegisterType<IPSecurity>().As<IIPSecurity>();
                //IDS
                builder.RegisterType<RuleChecking>().As<IRuleChecking>();
                builder.RegisterType<ReconChecking>().As<IReconChecking>();
                //LOG
                builder.RegisterType<DosService>().As<IDosService>();
                builder.RegisterType<SQLIService>().As<ISQLIService>();
                builder.RegisterType<XSSService>().As<IXSSService>();
                builder.RegisterType<FileUploadService>().As<IFileUploadService>();
                builder.RegisterType<IDSLogService>().As<IIDSLogService>();
                //ALERT
                builder.RegisterType<MailService>().As<IMailService>();
                builder.RegisterType<NotifyService>().As<INotifyService>();
            });
            
            var app = builder.Build();
            app.UseCors("AllowAll");
            //Configure the HTTP request pipeline.
            app.MapGrpcService<ProtobufSecurity>();
            app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");
            app.MapHub<AlertHub.AlertHub>("/alerthub");
            app.Run();
        }
    }
}