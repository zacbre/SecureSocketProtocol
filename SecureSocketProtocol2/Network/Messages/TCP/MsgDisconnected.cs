using SecureSocketProtocol2.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgDisconnected : IMessage
    {
        public DisconnectReason Reason;
        public MsgDisconnected(DisconnectReason Reason)
            : base()
        {
            this.Reason = Reason;
        }
        public MsgDisconnected()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, Plugin.IPlugin plugin = null)
        {
            SSPClient c = client as SSPClient;

            if (c != null)
            {
                c.ConnectionClosedNormal = true;
                if (!client.Connection.InvokedOnDisconnect)
                {
                    client.Connection.InvokedOnDisconnect = true;
                    c.Disconnect(Reason);
                }
            }
            base.ProcessPayload(client, plugin);
        }

        public override void WritePayload(IClient client, Plugin.IPlugin plugin = null)
        {


            base.WritePayload(client, plugin);
        }
    }
}
