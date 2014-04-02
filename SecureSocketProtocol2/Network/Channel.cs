using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public abstract class Channel
    {
        public Connection Connection { get; internal set; }
        public uint ConnectionId { get; internal set; }
        public ConnectionState State { get; internal set; }
        public SSPClient Client { get; internal set; }

        public abstract void onChannelOpen();
        public abstract void onChannelClosed();
        public abstract void onReceiveMessage(IMessage message);
        public abstract void onDeepPacketInspection(IMessage message);

        public Channel()
        {

        }

        public ChannelError SendMessage(IMessage message)
        {
            try
            {
                lock(Connection)
                {
                    if (State == ConnectionState.Closed)
                        return ChannelError.ChannelClosed;
                    Connection.SendMessage(message, PacketId.ChannelPayload, this);
                }
            }
            catch(Exception ex)
            {
                Client.onException(ex, ErrorType.Core);
            }
            return ChannelError.Unsuccessful;
        }

        public void CloseChannel()
        {
            try
            {
                lock(Connection)
                {
                    lock(Client.channels)
                    {
                        if (this.State == ConnectionState.Closed)
                            return;


                        Client.SharedChannel.CloseChannel(ConnectionId);
                        Client.channels.Remove(this.ConnectionId);
                        onChannelClosed();
                    }
                }
            }
            catch(Exception ex)
            {
                Client.onException(ex, ErrorType.Core);
            }
        }
    }
}