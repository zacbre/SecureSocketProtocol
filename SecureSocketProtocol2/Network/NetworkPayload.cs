using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class NetworkPayload
    {
        public byte[] Payload { get; set; }
        public int PacketSize { get; set; }
        public uint WriteOffset { get; set; }
        public bool ReceivedHeader { get; set; }
        public bool ReceivedPacket { get { return Payload.Length == PacketSize; } }
        public ReceiveCallback Callback { get; private set; }
        public SyncObject syncObject { get; private set; }
        public Connection Connection { get; private set; }
        public delegate byte[] EncryptPayloadCallback(bool usingCompression, int length, uint hash);
        public PacketHeader Header;

        public NetworkPayload(Connection Connection, SyncObject syncObject, ReceiveCallback callback = null)
        {
            this.PacketSize = Connection.HEADER_SIZE;
            this.Payload = new byte[PacketSize];
            this.WriteOffset = 0;
            this.ReceivedHeader = false;
            this.Callback = callback;
            this.syncObject = syncObject;
            this.Connection = Connection;
            this.Header = new PacketHeader(Connection);
        }

        ~NetworkPayload()
        {
            this.syncObject = null;
            this.Callback = null;
            this.Payload = null;
        }
    }
}
