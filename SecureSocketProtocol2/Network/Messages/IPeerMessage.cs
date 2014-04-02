using SecureSocketProtocol2.Network.RootSocket;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    public class IPeerMessage : IMessage
    {
        public decimal ConnectionId;
        internal RootPeer Peer;

        internal IPeerMessage(decimal ConnectionId)
            : base()
        {
            this.ConnectionId = ConnectionId;
        }
        public IPeerMessage()
            : base()
        {

        }

        public override void ProcessPayload(Interfaces.IClient client, Plugin.IPlugin plugin = null)
        {
            
        }
    }
}