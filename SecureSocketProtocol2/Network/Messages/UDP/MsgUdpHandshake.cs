using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.UDP
{
    internal class MsgUdpHandshake : IMessage
    {
        public byte[] HandshakeCode;
        public MsgUdpHandshake(byte[] HandshakeCode)
            : base()
        {
            this.HandshakeCode = HandshakeCode;
        }
        public MsgUdpHandshake()
            : base()
        {

        }
    }
}