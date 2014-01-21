using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgCloseChannel : IMessage
    {
        public ulong ConnectionId;

        public MsgCloseChannel()
            : base()
        {

        }

        public MsgCloseChannel(Channel channel)
            : base()
        {
            this.ConnectionId = channel.ConnectionId;
        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            lock (client.Connection.Client.channels)
            {
                if (client.Connection.Client.channels.ContainsKey(ConnectionId))
                {
                    client.Connection.Client.channels[ConnectionId].State = ConnectionState.Closed;

                    try
                    {
                        client.Connection.Client.channels[ConnectionId].onChannelClosed();
                    }
                    catch (Exception ex)
                    {
                        client.Connection.Client.onException(ex);
                    }
                    client.Connection.Client.channels.Remove(ConnectionId);
                }
            }
            base.ProcessPayload(client);
        }
    }
}
