using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgPacketQueue : IMessage
    {
        public byte[] Data;
        public MsgPacketQueue(byte[] Data)
            : base()
        {
            this.Data = Data;
        }
        public MsgPacketQueue()
            : base()
        {

        }
    }
}