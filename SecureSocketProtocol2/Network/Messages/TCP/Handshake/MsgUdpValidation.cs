using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgUdpValidation : IMessage
    {
        public byte[] Validation;

        public MsgUdpValidation()
            : base()
        {

        }

        public MsgUdpValidation(byte[] Validation)
            : base()
        {
            this.Validation = Validation;
        }
    }
}