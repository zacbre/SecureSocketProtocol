using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.RootSocket
{
    public class RootDnsInfo
    {
        public string DnsName { get; internal set; }
        public uint DnsId { get; internal set; }
        public string VirtualIp { get; internal set; }

        public RootDnsInfo(string DnsName, uint DnsId)
        {
            this.DnsName = DnsName;
            this.DnsId = DnsId;
        }
    }
}
