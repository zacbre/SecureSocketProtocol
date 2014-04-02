using SecureSocketProtocol2.Attributes;
using SecureSocketProtocol2.Interfaces.Shared;
using SecureSocketProtocol2.Network;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Shared.SharedClasses
{
    internal class SharedChannel : ISharedChannel
    {
        private Connection connection;
        public SharedChannel(Connection connection)
        {
            this.connection = connection;
        }

        [RemoteExecution(30000, null)]
        public void CloseChannel(ulong ConnectionId)
        {
            lock (connection.Client.channels)
            {
                if (connection.Client.channels.ContainsKey(ConnectionId))
                {
                    connection.Client.channels[ConnectionId].State = ConnectionState.Closed;

                    try
                    {
                        connection.Client.channels[ConnectionId].onChannelClosed();
                    }
                    catch (Exception ex)
                    {
                        connection.Client.onException(ex, ErrorType.UserLand);
                    }
                    connection.Client.channels.Remove(ConnectionId);
                }
            }
        }

        [UncheckedRemoteExecution]
        public void OpenChannel(Action<OpenChannelResponse> ResponseCallback)
        {
            if (ResponseCallback == null)
                return;

            try
            {
                if (!connection.Client.ChannelsAllowed)
                {
                    ResponseCallback(new OpenChannelResponse(0, false));
                }

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

                    ResponseCallback(new OpenChannelResponse(ConnectionId, success));

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
        }
    }
}