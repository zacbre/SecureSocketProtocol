using SecureSocketProtocol2.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.StreamMessages
{
    internal class MsgOpenStreamResponse : IMessage
    {
        public decimal StreamId;
        public MsgOpenStreamResponse(decimal StreamId)
            : base()
        {
            this.StreamId = StreamId;
        }

        public MsgOpenStreamResponse()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, Plugin.IPlugin plugin = null)
        {
            SecureStream stream = null;
            lock(client.Connection.Streams)
            {
                if(client.Connection.Streams.ContainsKey(StreamId))
                {
                    stream = client.Connection.Streams[StreamId];
                }
            }


            stream.StreamLock.Value = this;
            stream.StreamLock.Pulse();
            base.ProcessPayload(client, plugin);
        }
    }
}