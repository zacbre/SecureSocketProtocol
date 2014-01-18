using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    internal class MsgReconnect : IMessage
    {
        public decimal ClientId;
        public decimal Token;

        public MsgReconnect(decimal ClientId, decimal Token)
            : base()
        {
            this.ClientId = ClientId;
            this.Token = Token;
        }
        public MsgReconnect()
            : base()
        {

        }

        public override void ProcessPayload(Misc.IClient client, Plugin.IPlugin plugin = null)
        {

            base.ProcessPayload(client, plugin);
        }
    }
}