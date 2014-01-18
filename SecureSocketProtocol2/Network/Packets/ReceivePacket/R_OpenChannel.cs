using SecureSocketProtocol2.Network.Packets.SendPacket;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.ReceivePacket
{
    internal class R_OpenChannel : IReadPacket
    {
        public R_OpenChannel(byte[] payload)
            : base(payload)
        {

        }

        public override void ReadPayload(Connection connection)
        {
            try
            {
                lock(connection.client.channels)
                {
                    Random rnd = new Random(DateTime.Now.Millisecond);
                    ulong ConnectionId = (ulong)(rnd.Next() * rnd.Next());
                    while(connection.client.channels.ContainsKey(ConnectionId))
                        ConnectionId = (ulong)(rnd.Next() * rnd.Next());

                    bool success = false;
                    Channel channel = null;

                    try
                    {
                        channel = (Channel)Activator.CreateInstance(connection.client.baseChannel, connection.client.baseChannelArgs);
                        channel.Connection = connection;
                        channel.ConnectionId = ConnectionId;
                        channel.Client = connection.client;
                        channel.State = ConnectionState.Open;
                        connection.client.channels.Add(ConnectionId, channel);
                        success = true;
                    } catch { }

                    connection.SendPacket(new S_OpenChannelResponse(ConnectionId, success), PacketId.OpenChannelResponse);

                    if(success)
                    {
                        try
                        {
                            connection.client.onNewChannelOpen(channel);
                        } catch (Exception ex) { connection.client.onException(ex); }

                        try
                        {
                            channel.onChannelOpen();
                        } catch (Exception ex) { connection.client.onException(ex); }
                    }
                }
            }
            catch { }
        }
    }
}