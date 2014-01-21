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
        internal ulong ConnectionId { get; set; }
        public ConnectionState State { get; internal set; }
        public SSPClient Client { get; internal set; }

        public abstract void onChannelOpen();
        public abstract void onChannelClosed();
        public abstract void onReceiveData(IMessage message);

        public Channel()
        {

        }

        public ChannelError SendPacket(IMessage message)
        {
            try
            {
                lock(Connection)
                {
                    //todo: need to look at channels soon, haven't worked at channels for a while
                    /*if (State == ConnectionState.Closed)
                        return ChannelError.ChannelClosed;

                    int size = 0;
                    uint MsgId = Connection.messageHandler.GetMessageId(message.GetType());
                    byte[] msgData = message.WritePacket(message, ref size);
                    Array.Resize(ref msgData, size);

                    MsgChannelPayload payloadMessage = new MsgChannelPayload(this, msgData, MsgId);
                    Connection.SendPacket(payloadMessage, PacketId.ChannelPayload);*/
                }
            }
            catch(Exception ex)
            {
                Client.onException(ex);
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
                Client.onException(ex);
            }
        }
    }
}