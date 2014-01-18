using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.ReceivePacket
{
    class R_OpenChannelResponse : IReadPacket
    {
        public ulong ConnectionId { get; private set; }
        public bool Success { get; private set; }

        public R_OpenChannelResponse(byte[] payload)
            : base(payload)
        {

        }

        public override void ReadPayload(Connection connection)
        {
            this.ConnectionId = base.ReadULong();
            this.Success = base.ReadByte() == 1;
            connection.client.ChannelSyncObject.Value = this;
            connection.client.ChannelSyncObject.Pulse();
        }
    }
}