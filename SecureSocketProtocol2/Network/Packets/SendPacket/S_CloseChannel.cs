using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.SendPacket
{
    internal class S_CloseChannel : IWritePacket
    {
        public Channel channel { get; private set; }
        public S_CloseChannel(Channel channel)
            : base()
        {
            this.channel = channel;
        }

        public override byte[] WritePayload()
        {
            base.WriteULong(channel.ConnectionId);
            return base.ToByteArray();
        }
    }
}