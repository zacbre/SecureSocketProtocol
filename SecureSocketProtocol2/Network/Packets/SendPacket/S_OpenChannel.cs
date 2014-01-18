using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.SendPacket
{
    internal class S_OpenChannel : IWritePacket
    {
        public S_OpenChannel()
            : base()
        {

        }

        public override byte[] WritePayload()
        {
            //no need to contain data the server will return simply if successful or not with a connection id
            return new byte[1];
        }
    }
}