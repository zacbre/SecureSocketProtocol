using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.ReceivePacket
{
    class R_CloseChannel : IReadPacket
    {
        public R_CloseChannel(byte[] payload)
            : base(payload)
        {

        }

        public override void ReadPayload(Connection connection)
        {
            ulong ConnectionId = base.ReadULong();
            lock(connection.client.channels)
            {
                if(connection.client.channels.ContainsKey(ConnectionId))
                {
                    connection.client.channels[ConnectionId].State = ConnectionState.Closed;

                    try
                    {
                        connection.client.channels[ConnectionId].onChannelClosed();
                    }
                    catch(Exception ex)
                    {
                        connection.client.onException(ex);
                    }
                    connection.client.channels.Remove(ConnectionId);
                }
            }
        }
    }
}