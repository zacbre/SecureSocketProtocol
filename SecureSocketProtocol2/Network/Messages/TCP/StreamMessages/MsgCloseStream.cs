using SecureSocketProtocol2.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.StreamMessages
{
    internal class MsgCloseStream : IMessage
    {
        public decimal StreamId;

        public MsgCloseStream(decimal StreamId)
            : base()
        {
            this.StreamId = StreamId;
        }

        public MsgCloseStream()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, Plugin.IPlugin plugin = null)
        {
            lock (client.Connection.Streams)
            {
                if (client.Connection.Streams.ContainsKey(StreamId))
                {
                    client.Connection.Streams[StreamId].IsClosed = true;
                    client.Connection.Streams.Remove(StreamId);
                }
            }
        }
    }
}