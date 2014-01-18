using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.SendPacket
{
    internal class S_ChannelPayload : IWritePacket
    {
        public Channel channel { get; private set; }
        public byte[] Payload { get; private set; }
        public S_ChannelPayload(Channel channel, byte[] payload)
            : base()
        {
            this.channel = channel;
            this.Payload = payload;
        }

        public override byte[] WritePayload()
        {
            this.WriteULong(channel.ConnectionId);
            this.WriteBytes(this.Payload);
            return this.ToByteArray();
        }
    }
}