using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.ReceivePacket
{
    class R_ChannelPayload : IReadPacket
    {
        public int RawSize { get; set; }
        public R_ChannelPayload(byte[] payload)
            : base(payload)
        {

        }

        public override void ReadPayload(Connection connection)
        {
            ulong ConnectionId = base.ReadULong();
            byte[] payload = base.ReadBytes(base.Packet.Length - base.Offset);

            lock(connection.client.channels)
            {
                if(connection.client.channels.ContainsKey(ConnectionId))
                {
                    connection.client.channels[ConnectionId].onReceiveData(payload, RawSize);
                }
            }
        }
    }
}