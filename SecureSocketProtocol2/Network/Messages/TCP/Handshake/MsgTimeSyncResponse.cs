using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgTimeSyncResponse : IMessage
    {
        public long Time;
        public MsgTimeSyncResponse(long time)
            : base()
        {
            this.Time = time;
        }

        public MsgTimeSyncResponse()
            : base()
        {

        }
    }
}