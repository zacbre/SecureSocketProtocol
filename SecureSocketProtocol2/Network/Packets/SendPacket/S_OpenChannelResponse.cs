using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.SendPacket
{
    class S_OpenChannelResponse : IWritePacket
    {
        public ulong ConnectionId { get; private set; }
        public bool success { get; private set; }

        public S_OpenChannelResponse(ulong connectionId, bool success)
            : base()
        {
            this.ConnectionId = connectionId;
            this.success = success;
        }

        public override byte[] WritePayload()
        {
            base.WriteULong(this.ConnectionId);
            base.WriteByte(success ? (byte)1 : (byte)0);
            return base.ToByteArray();
        }
    }
}