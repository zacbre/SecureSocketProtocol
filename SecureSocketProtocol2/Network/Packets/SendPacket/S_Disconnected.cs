using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.SendPacket
{
    class S_Disconnected : IWritePacket
    {
        public override byte[] WritePayload()
        {
            return new byte[1];
        }
    }
}