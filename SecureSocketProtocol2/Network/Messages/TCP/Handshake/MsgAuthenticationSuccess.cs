using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgAuthenticationSuccess : IMessage
    {
        public bool Success;
        public MsgAuthenticationSuccess(bool Success)
            : base()
        {
            this.Success = Success;
        }
        public MsgAuthenticationSuccess()
            : base()
        {

        }
    }
}