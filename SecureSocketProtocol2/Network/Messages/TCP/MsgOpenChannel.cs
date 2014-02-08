using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgOpenChannel : IMessage
    {
        public uint ConnectionId;

        public MsgOpenChannel()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            try
            {
                Connection connection = client.Connection;
                lock (connection.Client.channels)
                {
                    Random rnd = new Random(DateTime.Now.Millisecond);
                    uint ConnectionId = (uint)(rnd.Next() * rnd.Next());
                    while (connection.Client.channels.ContainsKey(ConnectionId) || ConnectionId == 0)
                        ConnectionId = (uint)(rnd.Next() * rnd.Next());

                    bool success = false;
                    Channel channel = null;

                    try
                    {
                        channel = (Channel)Activator.CreateInstance(connection.Client.baseChannel, connection.Client.baseChannelArgs);
                        channel.Connection = connection;
                        channel.ConnectionId = ConnectionId;
                        channel.Client = connection.Client;
                        channel.State = ConnectionState.Open;
                        connection.Client.channels.Add(ConnectionId, channel);
                        success = true;
                    }
                    catch { }

                    connection.SendPacket(new MsgOpenChannelResponse(ConnectionId, success), PacketId.OpenChannelResponse);

                    if (success)
                    {
                        try
                        {
                            connection.Client.onNewChannelOpen(channel);
                        }
                        catch (Exception ex) { connection.Client.onException(ex, ErrorType.Core); }

                        try
                        {
                            channel.onChannelOpen();
                        }
                        catch (Exception ex) { connection.Client.onException(ex, ErrorType.Core); }
                    }
                }
            }
            catch { }
            base.WritePayload(client);
        }
    }
}
