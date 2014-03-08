using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgMessageSeed : IMessage
    {
        public uint Seed;

        public MsgMessageSeed()
            : base()
        {

        }

        public MsgMessageSeed(uint seed)
            : base()
        {
            this.Seed = seed;
        }
    }
}