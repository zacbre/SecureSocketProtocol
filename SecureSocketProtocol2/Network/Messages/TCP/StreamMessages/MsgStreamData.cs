using SecureSocketProtocol2.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network.Messages.TCP.StreamMessages
{
    internal class MsgStreamData : IMessage
    {
        public decimal StreamId;
        public byte[] data;

        public MsgStreamData(decimal StreamId, byte[] data)
            : base()
        {
            this.StreamId = StreamId;
            this.data = data;
        }
        public MsgStreamData()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, Plugin.IPlugin plugin = null)
        {
            lock (client.Connection.Streams)
            {
                if (client.Connection.Streams.ContainsKey(StreamId))
                {
                    while (client.Connection.Streams[StreamId].stream.Length > 30000)
                    {
                        client.Connection.Streams[StreamId].StreamLock.Wait<object>(null, 3000);
                        client.Connection.Streams[StreamId].StreamLock = new SyncObject(client);
                    }

                    lock (client.Connection.Streams[StreamId].FlushLock)
                    {
                        client.Connection.Streams[StreamId].stream.Write(data, 0, data.Length);
                        client.Connection.Streams[StreamId].ReadLock.Pulse();
                    }
                }
            }
            base.ProcessPayload(client, plugin);
        }
    }
}