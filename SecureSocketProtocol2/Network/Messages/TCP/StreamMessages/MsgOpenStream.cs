using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Network.Messages.TCP.Channels;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.StreamMessages
{
    internal class MsgOpenStream : IMessage
    {
        public decimal StreamId;
        public MsgOpenStream(decimal StreamId)
            : base()
        {
            this.StreamId = StreamId;
        }

        public MsgOpenStream()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, Plugin.IPlugin plugin = null)
        {
            SecureStream stream = new SecureStream(client, StreamId);
            lock (client.Connection.Streams)
            {
                if(!client.Connection.Streams.ContainsKey(StreamId))
                {
                    client.Connection.Streams.Add(stream.StreamId, stream);
                    client.Connection.SendPayload(new MsgOpenStreamResponse(this.StreamId), PacketId.StreamMessages);
                }
                else
                {
                    return;
                }
            }
            client.Connection.Client.onNewStreamOpen(stream);
            base.ProcessPayload(client, plugin);
        }
    }
}