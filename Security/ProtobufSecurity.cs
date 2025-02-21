using ALERT.MailService;
using ALERT.Model;
using ALERT.NotifyService;
using DASHBOARD_DBConnection.Entities;
using Grpc.Core;
using IDS_SECURITY.ReconDetection;
using IDS_SECURITY.RuleBasedDetection;
using LOGGER.DosService;
using LOGGER.FileUploadService;
using LOGGER.IDSLogService;
using LOGGER.Model.DOS;
using LOGGER.Model.FileUpload;
using LOGGER.Model.IDS;
using LOGGER.Model.SQLI;
using LOGGER.Model.XSS;
using LOGGER.SQLIService;
using LOGGER.XSSService;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using NET_SECURITY_MODEL.GrpcMessageModel;
using NET_SECURITY_MODEL.IDS.ReconModel;
using NET_SECURITY_MODEL.IDS.RuleModel;
using NET_SECURITY_MODEL.WAF.DOSModel;
using NET_SECURITY_MODEL.WAF.FileUploadModel;
using NET_SECURITY_MODEL.WAF.SQLIModel;
using NET_SECURITY_MODEL.WAF.XSSModel;
using Newtonsoft.Json;
using WAF_SECURITY.DOSSecurity;
using WAF_SECURITY.FileUploadSecurity;
using WAF_SECURITY.IPSecurity;
using WAF_SECURITY.SQLISecurity;
using WAF_SECURITY.XSSSecurity;

namespace NET_GRPC_SECURITY.Security
{
    public class ProtobufSecurity : Protobuf.ProtobufBase
    {
        //WAF Testing
        private readonly ITokenBucketService _token;
        private readonly ISQLITesting _sqli;
        private readonly IXSSTesting _xss;
        private readonly IFileUploadTesting _files;
        private readonly IIPSecurity _ips;
        //IDS Monitoring
        private readonly IRuleChecking _snort;
        private readonly IReconChecking _recon;
        //LOG 
        private readonly IDosService _doslog;
        private readonly ISQLIService _sqllog;
        private readonly IXSSService _xsslog;
        private readonly IFileUploadService _filelog;
        private readonly IIDSLogService _idslog;
        //ALERT
        private readonly IMailService _mail;
        private readonly INotifyService _notify;
        private readonly IHubContext<AlertHub.AlertHub> _hubContext;
        public ProtobufSecurity(ITokenBucketService token, ISQLITesting sqls, IXSSTesting xss, IFileUploadTesting files, IIPSecurity ips, IReconChecking recon, IRuleChecking snort, IDosService doslog, ISQLIService sqllog, IXSSService xsslog, IFileUploadService filelog, IIDSLogService idslog, IMailService mail, INotifyService notify, IHubContext<AlertHub.AlertHub> hubcontext)
        {
            _token = token;
            _sqli = sqls;
            _files = files;
            _ips = ips;
            _xss = xss;
            _snort = snort;
            _recon = recon;
            _doslog = doslog;
            _sqllog = sqllog;
            _xsslog = xsslog;
            _filelog = filelog;
            _idslog = idslog;
            _mail = mail;
            _notify = notify;
            _hubContext = hubcontext;
        }
        //RECEIVE REQUEST AND SCAN REQUEST (WAF-IDS/IPS-LOG)
        public override async Task<ResponseMessage> RequestVerificationAsync(RequestMessage message, ServerCallContext context)
        {
            //Bind AppConfig From Database
            AppConfiguration appConfig = context.GetHttpContext()
                .RequestServices.GetRequiredService<NetsecurityContext>()
                .AppConfigurations
                .Include(config => config.FileExtensionsNormals)
                .Include(config => config.FileExtensionsToScans)
                .FirstOrDefault();
            //Convert Message From Protobuff To Request Model 
            RequestModel request = ConvertMessageToModel(message);
            if (appConfig == null || request == null)
            {
                return await Task.FromResult(new ResponseMessage
                {
                    IsSecurity = false,
                    StatusCode = 500,
                    Message = "SYSTEM ERROR!"
                });
                throw new InvalidOperationException("AppConfiguration not found in the database");
            }
            ResponseMessage detect = new ResponseMessage();
            //WAF-Security (First Scan Module)
            detect = await WAFValidating(request, appConfig);
            if (detect.IsSecurity)
            {
                //IDS/IPS-Security(Second Scan Module)
                detect = await IDSValidating(request, appConfig);
            }
            if (!detect.IsSecurity)
            {
                if (detect.StatusCode != 451)
                    await _ips.CreateIPBlock(request.Source, detect.Message);
                return detect;
            }
            return await Task.FromResult(new ResponseMessage
            {
                IsSecurity = true,
                StatusCode = 204,
                Message = "SAFE REQUEST"
            });
        }

        //WAF - Security
        private async Task<ResponseMessage> WAFValidating(RequestModel request, AppConfiguration appConfig)
        {
            //Black List Implement 
            if (appConfig.BlockedIpenabled == true)
            {
                var block = await _ips.IsIPBlocked(request);
                if (block.IsViolated)
                    return new ResponseMessage
                    {
                        IsSecurity = false,
                        StatusCode = block.Status,
                        Message = block.Message,
                    };
            }
            //Rate Limit Implement 
            if (appConfig.RateLimitEnabled)
            {
                var result = _token.GetTokenBucket().UseToken();
                if (result.IsDrop)
                {
                    if (result.Status == 429)
                    {
                        await Loging("DOS", request, result);
                        await ALERT(appConfig, "Risk - Denial of service (dos)", "2", result.Message);
                    }
                    return new ResponseMessage
                    {
                        IsSecurity = false,
                        StatusCode = result.Status,
                        Message = result.Message,
                    };
                }
            }
            if (!request.HasFormContentType)
            {
                //Define Verify Sql Injection
                var checkSQLI = new List<Func<RequestModel, Task<SQLIInspect>>>
                  {
                      _sqli.IsEscapeSQLI,
                      _sqli.IsLogicalOperateSQLI,
                      _sqli.IsDefaultPatternSBSQLI,
                      _sqli.IsRExpressionSBSQLI,
                      _sqli.IsCRSRuleSBSQLI,
                      _sqli.IsCTRuleSBSQLI
                  };
                foreach (var sqlinjection in checkSQLI)
                {
                    SQLIInspect verify = await sqlinjection(request);
                    if (verify.IsViolated)
                    {
                        if (verify.Status == 403)
                        {
                            await Loging("SQLI", request, verify);
                            await ALERT(appConfig, "Detects SQL-Injection Violate", verify.Level.ToString(), verify.Message);
                        }
                        return new ResponseMessage
                        {
                            IsSecurity = false,
                            StatusCode = verify.Status,
                            Message = verify.Message,
                        };
                    }
                }
                //Define Verify Xss 
                var checkXSS = new List<Func<RequestModel, Task<XSSInspect>>>
                  {
                      _xss.IsDefaultPatternSBXSS,
                      _xss.IsCRSRuleSBXSS,
                      _xss.IsCTRuleSBXSS
                  };
                foreach (var xss in checkXSS)
                {
                    XSSInspect verify = await xss(request);
                    if (verify.IsViolated)
                    {
                        if (verify.Status == 403)
                        {
                            await Loging("XSS", request, verify);
                            await ALERT(appConfig, "Detects XSS Violate", verify.Level.ToString(), verify.Message);
                        }
                        return new ResponseMessage
                        {
                            IsSecurity = false,
                            StatusCode = verify.Status,
                            Message = verify.Message,
                        };
                    }
                }
            }
            //Define Verify File Upload
            if (request.HasFormContentType)
            {
                FILEInspect verify = new FILEInspect();
                List<FileModel> files = request.Files.Where(p => appConfig.FileExtensionsNormals.Any(a => a.Extension.Equals(Path.GetExtension(p.FileName), StringComparison.OrdinalIgnoreCase))).ToList();
                if (files != null && files.Any())
                {
                    verify = await _files.InspectFileExtension(request.Files);
                    if (!verify.IsClean)
                    {
                        if (verify.Status == 400)
                        {
                            await Loging("FILE", request, verify);
                            await ALERT(appConfig, "Detects File Incorrect Signature Extension.", "2", verify.Message);
                        }
                        return new ResponseMessage
                        {
                            IsSecurity = false,
                            StatusCode = verify.Status,
                            Message = verify.Message
                        };
                    }
                }
                if (appConfig.InspectFileEnabled)
                {
                    files = new List<FileModel>();
                    files = request.Files.Where(p => appConfig.FileExtensionsToScans.Any(a => a.Extension.Equals(Path.GetExtension(p.FileName), StringComparison.OrdinalIgnoreCase))).ToList();
                    if (files != null && files.Any())
                    {
                        verify = await _files.InspectFileMalware(request.Files);
                        if (!verify.IsClean)
                        {
                            if (verify.Status == 400)
                            {
                                await Loging("FILE", request, verify);
                                await ALERT(appConfig, "Detects File-Virus Or File-Malware","3", verify.Message);
                            }
                            return new ResponseMessage
                            {
                                IsSecurity = false,
                                StatusCode = verify.Status,
                                Message = verify.Message
                            };
                        }
                    }
                }
            }
            //Verify Finish
            return await Task.FromResult(new ResponseMessage
            {
                IsSecurity = true,
                StatusCode = 204,
                Message = "WAF - Request No Violation!"
            });
        }

        //IDS-IPS Monitoring/Drropping
        private async Task<ResponseMessage> IDSValidating(RequestModel request, AppConfiguration appConfig)
        {
            //Define Checking Recon
            var checRecon = new List<Func<RequestModel, Task<ReconInspect>>>
                  {
                      _recon.IsReconValidate,
                  };
            foreach (var recon in checRecon)
            {
                ReconInspect verify = await recon(request);
                if (verify.IsViolated)
                {
                    await Loging("IDS", request, verify);
                    await ALERT(appConfig, "Detects suspicious requests","1", verify.Message);
                }
            }
            //Define Checking Rules
            var checkSign = new List<Func<RequestModel, Task<RuleMatcher>>>
                  {
                      _snort.IsVRuleIDS,
                      _snort.IsCTRuleIDS
                  };
            foreach (var task in checkSign)
            {
                RuleMatcher verify = await task(request);
                if (verify.IsViolated)
                {
                    if (verify.Status == 403)
                    {
                        await Loging("IDS", request, verify);
                        await ALERT(appConfig, "Detects suspicious requests", verify.Level.ToString(), verify.Message);
                    }
                    return new ResponseMessage
                    {
                        IsSecurity = appConfig.IntegrateIpsenabled ? false : true,
                        StatusCode = appConfig.IntegrateIpsenabled ? verify.Status : 204,
                        Message = verify.Message
                    };
                }
            }
            //Monitor Finish
            return await Task.FromResult(new ResponseMessage
            {
                IsSecurity = true,
                StatusCode = 204,
                Message = "IPS/IDS - Request No Suspicious!"
            });
        }

        //LOG
        private async Task Loging(string type, RequestModel request, object model)
        {
            try
            {
                var createdDate = DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss");
                string source = request.Source;
                string url = request.Path + request.QueryString;
                string paramValue = request.Body;
                string method = request.Method;
                string protocol = request.Protocol;
                string contentType = request.ContentType;
                string action = request.Action;
                // Create logging view model based on type
                bool islog = false;
                switch (type)
                {
                    case "DOS":
                        if (model is DOSInspect dos)
                        {
                            var dosLog = new DOSViewModel
                            {
                                Message = dos.Message,
                                CreatedDate = createdDate,
                                Source = source,
                                Url = url,
                                ParamValue = paramValue,
                                Method = method,
                                Protocal = protocol,
                                ContentType = contentType,
                                Action = action
                            };
                            islog = await _doslog.CreateAsync(dosLog);
                        }
                        break;
                    case "SQLI":
                        if (model is SQLIInspect sqli)
                        {
                            var sqliLog = new SQLIViewModel
                            {
                                Message = sqli.Message,
                                Level = sqli.Level.ToString(),
                                CreatedDate = createdDate,
                                Source = source,
                                Url = url,
                                ParamValue = paramValue,
                                Method = method,
                                Protocal = protocol,
                                ContentType = contentType,
                                Action = action
                            };
                            islog = await _sqllog.CreateAsync(sqliLog);
                        }
                        break;
                    case "XSS":
                        if (model is XSSInspect xssi)
                        {
                            var xssLog = new XSSViewModel
                            {
                                Message = xssi.Message,
                                Level = xssi.Level,
                                CreatedDate = createdDate,
                                Source = source,
                                Url = url,
                                ParamValue = paramValue,
                                Method = method,
                                Protocal = protocol,
                                ContentType = contentType,
                                Action = action
                            };
                            islog = await _xsslog.CreateAsync(xssLog);
                        }
                        break;
                    case "FILE":
                        if (model is FILEInspect filei)
                        {
                            var fileLog = new FileUploadViewModel
                            {
                                Message = filei.Message,
                                Source = source,
                                Url = url,
                                Filename = filei.FileName,
                                Filehash = filei.FileHash,
                                Action = action
                            };
                            islog = await _filelog.CreateAsync(fileLog);
                        }
                        break;
                    case "IDS":
                        if (model is RuleMatcher idsr)
                        {
                            var idslog = new IDSLogViewModel
                            {
                                Message = idsr.Message,
                                Level = idsr.Level.ToString(),
                                CreatedDate = createdDate,
                                Source = source,
                                Url = url,
                                ParamValue = paramValue,
                                Method = method,
                                Protocal = protocol,
                                ContentType = contentType,
                                Action = action
                            };
                            islog = await _idslog.CreateAsync(idslog);
                        }
                        else if (model is ReconInspect idsb)
                        {
                            var idslog = new IDSLogViewModel
                            {
                                Message = idsb.Message,
                                Level = "1",
                                CreatedDate = createdDate,
                                Source = source,
                                Url = url,
                                ParamValue = paramValue,
                                Method = method,
                                Protocal = protocol,
                                ContentType = contentType,
                                Action = action
                            };
                            islog = await _idslog.CreateAsync(idslog);
                        }
                        break;
                }
                if (!islog)
                    Console.WriteLine($"Logging  {type} Unsuccessful!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Logging Unsuccessful - Error: {ex.Message}");
            }
        }
        //ALERT
        private async Task ALERT(AppConfiguration config, string title, string level, string message)
        {
            try
            {

                AlertViewModel alert = new AlertViewModel()
                {
                    Header = title,
                    Message = message,
                    Level = level
                };
                if (config.EmailNotificationEnable == true)
                    await _mail.SendEmailAsync(alert);
                await _notify.CreateNotifyAsync(title, message, "");
                await _hubContext.Clients.All.SendAsync("ALERTS", JsonConvert.SerializeObject(alert));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Alert Unsuccessful - Error: {ex.Message}");
            }
        }
        //CONVERT
        private RequestModel ConvertMessageToModel(RequestMessage message)
        {
            if (message != null)
            {
                //Convert message -> model
                var request = new RequestModel
                {
                    Method = message.Method,
                    Path = message.Path,
                    Protocol = message.Protocol,
                    Source = message.Source,
                    QueryString = message.QueryString,
                    ContentLength = message.ContentLength,
                    ContentType = message.ContentType,
                    Headers = message.Headers,
                    Queries = message.Queries,
                    Cookies = message.Cookies,
                    Body = message.Body,
                    Action = message.Action,
                    HasFormContentType = message.HasFormContentType
                };
                if (message.HasFormContentType && (request.Method == "POST" || request.Method == "PUT" || request.Method == "PATCH"))
                {
                    foreach (var item in message.Files)
                    {
                        request.Files.Add(new FileModel
                        {
                            FileContent = item.FileContent.ToByteArray(),
                            Length = item.Length,
                            FileHash = item.FileHash,
                            FileName = item.FileName
                        });
                    }
                }
                return request;
            }
            return null;
        }
    }
}
