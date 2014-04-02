using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.RootSocket
{
    internal class MsgRootDnsResponse : IMessage
    {
        public string VirtualIp;
        public decimal RequestId;

        public MsgRootDnsResponse(string VirtualIp, decimal RequestId)
            : base()
        {
            this.VirtualIp = VirtualIp;
            this.RequestId = RequestId;
        }
        public MsgRootDnsResponse()
            : base()
        {

        }

        public override void ProcessPayload(Interfaces.IClient client, Plugin.IPlugin plugin = null)
        {
            
        }
    }
}