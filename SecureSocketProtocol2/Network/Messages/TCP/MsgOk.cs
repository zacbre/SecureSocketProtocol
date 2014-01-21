using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgOk : IMessage
    {
        public byte[] Zero = new byte[0];
        public MsgOk()
            : base()
        {

        }
    }
}