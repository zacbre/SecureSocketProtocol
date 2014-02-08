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
                    Connection.SendPacket(message, PacketId.ChannelPayload, true, true, this);
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

                        this.State = ConnectionState.Closed;
                        Connection.SendPacket(new MsgCloseChannel(this), PacketId.CloseChannel, true);
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