using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    internal class OptimizedNetworkStream
    {
        internal ReceiveType ReceiveState = ReceiveType.Header;
        public const int DefaultSize = 70000;
        private Action<OptimizedNetworkStream> StreamCallback;
        public NetworkPayload NetworkPayload;
        public byte[] Buffer;
        public int DataAvailable = 0;
        public int Position = 0;

        public OptimizedNetworkStream(Connection Connection, Action<OptimizedNetworkStream> StreamCallback)
        {
            this.Buffer = new byte[DefaultSize];
            this.StreamCallback = StreamCallback;
            this.NetworkPayload = new NetworkPayload(Connection, null);
        }

        public int Read(ref byte[] buffer, int offset, int count)
        {
            lock (Buffer)
            {
                if (this.Position + count <= Buffer.Length && count <= DataAvailable)
                {
                    Array.Copy(this.Buffer, this.Position, buffer, offset, count);
                    this.Position += count;
                    this.DataAvailable -= count;
                    return count;
                }
            }
            return 0;
        }
    }
}