using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Interfaces.Shared
{
    [Serializable]
    public class PeerResponse
    {
        public PeerErrorCode ErrorCode { get; private set; }
        public decimal ConnectionId { get; private set; }
        public string VirtualIP { get; private set; }

        public PeerResponse(PeerErrorCode ErrorCode, decimal ConnectionId, string VirtualIP)
        {
            this.ErrorCode = ErrorCode;
            this.ConnectionId = ConnectionId;
            this.VirtualIP = VirtualIP;
        }
    }

    public interface ISharedRoot
    {
        string ResolveDns(string DnsName);
        DnsErrorCode RegisterDns(string DnsName);
        PeerResponse ConnectToPeer(string VirtualIpOrDns);
    }
}