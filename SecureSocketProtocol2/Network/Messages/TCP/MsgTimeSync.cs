using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgTimeSync : IMessage
    {
        public long Time;

        public MsgTimeSync(DateTime time)
            : base()
        {
            this.Time = time.ToBinary();
        }

        public MsgTimeSync()
            : base()
        {

        }
    }
}