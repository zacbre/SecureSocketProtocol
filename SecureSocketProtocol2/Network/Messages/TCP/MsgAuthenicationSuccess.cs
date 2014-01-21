using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgAuthenicationSuccess : IMessage
    {
        public bool Success;
        public MsgAuthenicationSuccess(bool Success)
            : base()
        {
            this.Success = Success;
        }
        public MsgAuthenicationSuccess()
            : base()
        {

        }
    }
}