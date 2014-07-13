using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgGetNextId : IMessage
    {
        public decimal RandomId;

        public MsgGetNextId()
            : base()
        {

        }

        public override void ProcessPayload(Interfaces.IClient client, Plugin.IPlugin plugin = null)
        {
            SSPClient Client = client as SSPClient;
            if (Client.PeerSide == PeerSide.Client)
            {
                if (Client.SyncNextRandomId != null)
                {
                    Client.SyncNextRandomId.Value = this;
                    Client.SyncNextRandomId.Pulse();
                }
            }
            else if (Client.PeerSide == PeerSide.Server)
            {
                RandomId = Client.Server.Random.NextDecimal();
                client.Connection.SendMessage(this, PacketId.RequestMessages);
            }
            base.ProcessPayload(client, plugin);
        }
    }
}