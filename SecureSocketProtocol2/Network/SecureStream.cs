using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages.TCP.StreamMessages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    public class SecureStream : System.IO.Stream
    {
        internal MemoryStream stream { get; private set; }
        internal decimal StreamId { get; set; }
        internal IClient Client { get; private set; }
        internal SyncObject StreamLock { get; set; }
        internal SyncObject ReadLock { get; set; }
        internal object FlushLock { get; private set; }
        private bool _isClosed = false;

        public SecureStream(IClient client, decimal StreamId)
            : base()
        {
            this.FlushLock = new object();
            this.stream = new MemoryStream();
            this.Client = client;
            this.StreamId = StreamId;
            this.IsOpen = true;
        }

        public SecureStream(IClient client)
            : base()
        {
            this.FlushLock = new object();
            this.stream = new MemoryStream();
            this.Client = client;

            lock(client.Connection)
            {
                RandomDecimal rnd = new RandomDecimal(DateTime.Now.Millisecond);
                StreamId = rnd.NextDecimal();
                while(client.Connection.Streams.ContainsKey(StreamId))
                    StreamId = rnd.NextDecimal();

                client.Connection.Streams.Add(StreamId, this);
                this.StreamLock = new SyncObject(client);
                client.Connection.SendMessage(new MsgOpenStream(this.StreamId), PacketId.StreamMessages);

                MsgOpenStreamResponse response = StreamLock.Wait<MsgOpenStreamResponse>(default(MsgOpenStreamResponse), 30000);

                if (response == null)
                    throw new TimeoutException("It took too long for the remote host to setup the Stream");

                IsOpen = true;
                this.StreamLock = new SyncObject(client);
                this.ReadLock = new SyncObject(client);
            }
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override bool CanTimeout
        {
            get { return true; }
        }

        public override int ReadTimeout
        {
            get;
            set;
        }

        public override int WriteTimeout
        {
            get;
            set;
        }

        public bool IsClosed
        {
            get { return _isClosed; }
            internal set
            {
                _isClosed = value;

                if(value)
                {
                    ReadLock.Pulse();
                    StreamLock.Pulse();
                    stream.Dispose();
                }
            }
        }

        public override void Flush()
        {
            if (IsClosed)
                throw new IOException("The SecureStream is closed.");

            lock(FlushLock)
            {
                stream.Position = 0;
                byte[] TempBuffer = new byte[60000];
                while(stream.Length > 0)
                {
                    int read = stream.Read(TempBuffer, 0, TempBuffer.Length);
                    if (read == 0)
                        break;
                    Array.Resize(ref TempBuffer, read);
                    Client.Connection.SendMessage(new MsgStreamData(this.StreamId, TempBuffer), PacketId.StreamMessages);
                }
                stream.Position = 0;
                stream.SetLength(0);
            }
        }

        /// <summary>
        /// the length of bytes that is in the buffer
        /// </summary>
        public override long Length
        {
            get { return stream.Length; }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public bool IsOpen { get; private set; }
        
        /// <summary> Automatically flushes at Write and sends data to the remote host </summary>
        public bool AutoFlush { get; set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            while (stream.Length == 0)
            {
                ReadLock.Wait<object>(null, (uint)this.ReadTimeout);
                ReadLock = new SyncObject(Client);

                //maybe needs to be remove but still... there was a time out set on it
                if (stream.Length == 0)
                {
                    return 0;
                }
                ReadLock = new SyncObject(Client);
            }

            lock (FlushLock)
            {
                stream.Position = 0;
                int read = stream.Read(buffer, offset, count);

                //need a better method soon
                int size = (int)(stream.Length - stream.Position);
                byte[] temp = new byte[size];
                stream.Read(temp, 0, size);
                this.stream = new MemoryStream();
                this.stream.Write(temp, 0, temp.Length);

                StreamLock.Pulse();
                return read;
            }
        }

        public override long Seek(long offset, System.IO.SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (IsClosed)
                throw new IOException("The SecureStream is closed.");

            lock (FlushLock)
            {
                this.stream.Write(buffer, offset, count);

                if (AutoFlush)
                {
                    Flush();
                }
            }
        }

        public override void Close()
        {
            IsClosed = true;
            Client.Connection.SendMessage(new MsgCloseStream(this.StreamId), PacketId.StreamMessages);
            base.Close();
        }
    }
}