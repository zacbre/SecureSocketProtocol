using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.RootSocket
{
    internal class MsgRootDnsRequest : IMessage
    {
        public string DnsName;
        public decimal RequestId;

        public MsgRootDnsRequest(string DnsName, decimal RequestId)
            : base()
        {
            this.DnsName = DnsName;
            this.RequestId = RequestId;
        }

        public override void ProcessPayload(Interfaces.IClient client, Plugin.IPlugin plugin = null)
        {

            base.ProcessPayload(client, plugin);
        }
    }
}