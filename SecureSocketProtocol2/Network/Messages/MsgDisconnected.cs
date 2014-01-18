using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    internal class MsgDisconnected : IMessage
    {
        public MsgDisconnected()
            : base()
        {

        }

        public override void ProcessPayload(Misc.IClient client, Plugin.IPlugin plugin = null)
        {
            SSPClient c = client as SSPClient;

            if (c != null)
            {
                c.ConnectionClosedNormal = true;
                c.Disconnect();
            }
            base.ProcessPayload(client, plugin);
        }

        public override void WritePayload(Misc.IClient client, Plugin.IPlugin plugin = null)
        {


            base.WritePayload(client, plugin);
        }
    }
}
