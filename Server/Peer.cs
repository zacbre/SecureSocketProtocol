using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.RootSocket;
using System;
using System.Collections.Generic;
using System.Text;

namespace Server
{
    public class Peer : RootPeer
    {
        public Peer()
            : base()
        {

        }

        public override void onReceiveMessage(IPeerMessage message)
        {

        }

        public override void onRegisterMessages(MessageHandler messageHandler)
        {

        }

        public override void onClientConnect()
        {

        }

        public override void onDisconnect(SecureSocketProtocol2.DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, SecureSocketProtocol2.ErrorType errorType)
        {

        }
    }
}
