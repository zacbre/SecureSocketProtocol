using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgClientInfo : IMessage
    {
        public decimal ClientId;
        public decimal Token;
        public byte[] UdpHandshakeCode;
        public string VirtualIP;

        public MsgClientInfo()
            : base()
        {

        }

        public MsgClientInfo(decimal ClientId, byte[] UdpHandshakeCode, decimal Token, string VirtualIP)
            : base()
        {
            this.ClientId = ClientId;
            this.UdpHandshakeCode = UdpHandshakeCode;
            this.Token = Token;
            this.VirtualIP = VirtualIP;
        }
    }
}