using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets
{
    public abstract class IWritePacket : PayloadWriter
    {
        public abstract byte[] WritePayload();
    }
}