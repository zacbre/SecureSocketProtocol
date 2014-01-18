using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets
{
    public abstract class IReadPacket : PayloadReader
    {
        public IReadPacket(byte[] payload)
            : base(payload)
        {

        }

        public abstract void ReadPayload(Connection connection);
    }
}