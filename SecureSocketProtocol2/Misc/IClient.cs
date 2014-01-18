using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    public interface IClient
    {
        Connection Connection { get; set; }
        void onReceiveMessage(IMessage message);
        void onClientConnect();
        void onDisconnect();
        void onDeepPacketInspection(IMessage message);
        void onException(Exception ex);
        void onRegisterMessages(MessageHandler messageHandler);
        void Disconnect();
        SSPError SendMessage(IMessage message, bool compress = true, bool cache = true);
    }
}