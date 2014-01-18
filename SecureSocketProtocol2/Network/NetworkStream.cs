using SecureSocketProtocol2;
using SecureSocketProtocol2.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    public class NetworkStream
    {
        public byte[] Buffer;
        public int Position = 0;
        public Action<NetworkStream> StreamCallback;
        public NetworkPayload NetworkPayload;
        public bool MultiThreaded = false;
        public int Length { get { return Buffer.Length; } }
        public ReceiveType ReceiveState = ReceiveType.Header;
        public Connection connection;

        public NetworkStream(Connection Connection, Action<NetworkStream> StreamCallback)
        {
            this.connection = Connection;
            this.Buffer = new byte[0];
            this.StreamCallback = StreamCallback;
            this.NetworkPayload = new NetworkPayload(Connection, null);
        }

        public int Read(ref byte[] buffer, int offset, int count)
        {
            lock (Buffer)
            {
                if (this.Position + count <= Buffer.Length)
                {
                    Array.Copy(this.Buffer, this.Position, buffer, offset, count);
                    this.Position += count;
                    return count;
                }
            }
            return 0;
        }

        public bool CanRead(int count)
        {
            return this.Position + count <= Buffer.Length;
        }

        /// <summary>
        /// This is the faster version of the normal Read method, since it's not using the Array.Copy
        /// </summary>
        public unsafe byte* Read(int count)
        {
            lock (Buffer)
            {
                if (this.Position + count <= Buffer.Length)
                {
                    fixed(byte* ptr = &(Buffer[this.Position]))
                    {
                        this.Position += count;
                        return ptr;
                    }
                }
            }
            return (byte*)0;
        }

        public int Flush()
        {
            Array.Copy(Buffer, this.Position, Buffer, 0, this.Buffer.Length - this.Position);
            Array.Resize(ref Buffer, (int)(Buffer.Length - this.Position));
            this.Position = 0;
            return Buffer.Length;
        }

        public int Write(byte[] buffer, int offset, int count)
        {
            lock (Buffer)
            {
                int WriteOffset = Buffer.Length;
                Array.Resize(ref this.Buffer, (int)(Buffer.Length + count));
                Array.Copy(buffer, offset, this.Buffer, WriteOffset, count);

                if (MultiThreaded)
                {
                    lock (Buffer)
                    {
                        ThreadPool.QueueUserWorkItem((object o) => StreamCallback(this));
                    }
                }
                else
                {
                    try
                    {
                        StreamCallback(this);
                    }
                    catch(Exception ex)
                    {
                        connection.Client.onException(ex);
                    }
                }
            }
            return 0;
        }
    }
}