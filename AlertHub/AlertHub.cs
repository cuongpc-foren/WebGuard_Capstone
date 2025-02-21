using Microsoft.AspNetCore.SignalR;

namespace NET_GRPC_SECURITY.AlertHub
{
    public class AlertHub:Hub
    {
        public async Task SendMessage(string user, string message)
      => await Clients.All.SendAsync("ReceiveMessage", user, message);
    }
}
