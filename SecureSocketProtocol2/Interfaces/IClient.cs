using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Interfaces
{
    public interface IClient
    {
        Connection Connection { get; set; }
        void onClientConnect();
        void onDisconnect(DisconnectReason Reason);
        void onException(Exception ex, ErrorType errorType);
        void onShareClasses();
        void Disconnect();
    }
}