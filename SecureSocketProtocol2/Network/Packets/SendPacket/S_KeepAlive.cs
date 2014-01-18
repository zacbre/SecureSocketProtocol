using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.SendPacket
{
    internal class S_KeepAlive : IWritePacket
    {
        public S_KeepAlive()
            : base()
        {

        }

        public override byte[] WritePayload()
        {
            //no data is required in the packet
            return new byte[1];
        }
    }
}