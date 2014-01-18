using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.ReceivePacket
{
    class R_Disconnected : IReadPacket
    {
        public R_Disconnected(byte[] payload)
            : base(payload)
        {

        }

        public override void ReadPayload(Connection connection)
        {

        }
    }
}