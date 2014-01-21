using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgChannelPayload : IMessage
    {
        public byte[] Payload;
        public ulong ConnectionId;
        public uint MessageId;

        public MsgChannelPayload()
            : base()
        {

        }

        public MsgChannelPayload(Channel channel, byte[] payload, uint MessageId)
            : base()
        {
            this.ConnectionId = channel.ConnectionId;
            this.Payload = payload;
            this.MessageId = MessageId;
        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            lock (client.Connection.Client.channels)
            {
                Channel channel = null;
                if (client.Connection.Client.channels.TryGetValue(ConnectionId, out channel))
                {
                    try
                    {
                        IMessage message = client.Connection.messageHandler.HandleMessage(new PayloadReader(Payload), MessageId);
                        if (message != null)
                        {
                            message.RawSize = base.RawSize;
                            channel.onReceiveData(message);
                        }
                    }
                    catch(Exception ex)
                    {
                        client.onException(ex);
                    }
                }
            }
            base.ProcessPayload(client);
        }
    }
}