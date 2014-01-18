using SecureSocketProtocol2.Compressions;
using SecureSocketProtocol2.Compressions.LZ4;
using SecureSocketProtocol2.Compressions.LZMA;
using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Protections;
using SecureSocketProtocol2.Network.Protections.Cache;
using SecureSocketProtocol2.Network.Protections.Compression;
using SecureSocketProtocol2.Network.Protections.Encryption;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    public class Connection
    {
        internal const ReceivePerformance ProcessSpeed = ReceivePerformance.Safe;
        public const int MAX_PAYLOAD = 10000000;
        public const int MAX_CACHE_SIZE = 1000000; //decrease value to reduce memory usage
        public const int RSA_KEY_SIZE = 2048; //change to a higher value if you feel paranoid

        public int HEADER_SIZE
        {
            get
            {
                return (int)(25 + protection.LayerCount + Client.HeaderTrashCount);
            }
        }


        public SSPClient Client { get; private set; }
        public ulong BytesOut { get; private set; }
        public ulong BytesIn { get; private set; }

        //Security stuff
        public DeepPacketInspection DPI { get; internal set; }
        private ushort CurPacketId = 0;
        private object ClientSendLock = new object();

        internal Protection protection { get; private set; }
        public bool UsingPrivateKey { get { return protection.UsingPrivateKey; } }
        private SocketAsyncEventArgs asyncReceiveEvent;
        private NetworkStream stream;
        private PacketQueue packetQueue;
        public PluginSystem pluginSystem { get; private set; }

        //just some queue's to make everything more simple
        //just also incase you want to open/close channels while you're receiving data
        private TaskQueue<IMessage> ChannelPayloadQueue;
        private TaskQueue<IMessage> CloseChannelQueue;
        private TaskQueue<IMessage> DisconnectedQueue;
        private TaskQueue<IMessage> OpenChannelQueue;
        private TaskQueue<IMessage> OpenChannelResponseQueue;
        private TaskQueue<IMessage> PacketTaskQueue;
        private TaskQueue<IMessage> PayloadQueue;
        private TaskQueue<IMessage> KeepAliveQueue;
        private TaskQueue<PluginRecvInfo> PluginDataQueue;

        internal Stopwatch KeepAliveSW = new Stopwatch();
        internal Stopwatch LastPacketSW = new Stopwatch();
        internal MessageHandler messageHandler;

        internal static readonly byte[] VALIDATION = new byte[]
        {
            151, 221, 126, 222, 126, 142, 126, 208, 107, 209, 212, 218, 228, 167, 158, 252, 105, 147, 185, 178,
            239, 238, 156, 228, 202, 141, 199, 198, 168, 199, 186, 121, 173, 166, 139, 225, 118, 162, 112, 252,
            208, 253, 200, 163, 161, 113, 200, 118, 206, 203, 252, 242, 202, 124, 107, 165, 224, 205, 221, 184,
            153, 161, 215, 146, 246, 166, 247, 135, 247, 107, 223, 160, 126, 193, 150, 248, 187, 219, 141, 211,
            135, 227, 157, 107, 184, 183, 125, 161, 142, 194, 150, 201, 224, 146, 210, 130, 244, 202, 181, 228
        };

        private Socket Handle
        {
            get { return Client.Handle; }
        }

        public bool Connected { get; internal set; }

        public Connection(SSPClient client)
        {
            this.Client = client;
            this.Connected = true;
            this.DPI = new DeepPacketInspection(this);
            this.Client.Handle.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            this.Client.Handle.NoDelay = true;

            this.packetQueue = new PacketQueue(this);
            this.ChannelPayloadQueue = new TaskQueue<IMessage>(client, onChannelPayloadQueue, 100);
            this.CloseChannelQueue = new TaskQueue<IMessage>(client, onCloseChannelQueue, 100);
            this.DisconnectedQueue = new TaskQueue<IMessage>(client, onDisconnectedQueue, 100);
            this.OpenChannelQueue = new TaskQueue<IMessage>(client, onOpenChannelQueue, 100);
            this.OpenChannelResponseQueue = new TaskQueue<IMessage>(client, onOpenChannelResponseQueue, 100);
            this.PacketTaskQueue = new TaskQueue<IMessage>(client, onPacketTaskQueue, 10);
            this.PayloadQueue = new TaskQueue<IMessage>(client, onPayloadQueue, 100);
            this.KeepAliveQueue = new TaskQueue<IMessage>(client, onKeepAliveQueue, 10);
            this.PluginDataQueue = new TaskQueue<PluginRecvInfo>(client, onPluginDataQueue, 100);
            this.messageHandler = new MessageHandler(0);
            this.pluginSystem = new PluginSystem(client);
            this.protection = new Protection(this);
        }


        /// <summary>
        /// Used to keep receiving data from it's destination
        /// </summary>
        internal void StartNetworkStream()
        {
            if (stream != null)
                return; //don't start the network stream twice

            this.stream = new NetworkStream(this, networkStreamCallback);

            asyncReceiveEvent = new SocketAsyncEventArgs();
            asyncReceiveEvent.Completed += AsyncSocketCallback;
            //asyncReceiveEvent.SetBuffer(stream.Buffer, 0, stream.Buffer.Length);

            asyncReceiveEvent.SetBuffer(new byte[70000], 0, 70000);
            if (!Handle.ReceiveAsync(asyncReceiveEvent))
                AsyncSocketCallback(null, this.asyncReceiveEvent);
        }

        private void AsyncSocketCallback(object o, SocketAsyncEventArgs e)
        {
            if (e.SocketError == SocketError.SocketError || e.BytesTransferred == 0)
            {
                try
                {
                    Client.Disconnect();
                }
                catch (Exception ex)
                {
                    Client.onException(ex);
                }
                return;
            }

            this.LastPacketSW = Stopwatch.StartNew();

            switch (e.LastOperation)
            {
                case SocketAsyncOperation.Receive:
                {
                    try
                    {
                        //let's check the certificate
                        if (Client.Certificate.ValidFrom > DateTime.Now)
                        {
                            //we need to wait till the time is right
                            Client.Disconnect();
                            return;
                        }
                        if (Client.Certificate.ValidTo < DateTime.Now)
                        {
                            //certificate is not valid anymore
                            Client.Disconnect();
                            return;
                        }



                        BytesIn += (ulong)e.BytesTransferred;
                        //to make it 2x faster remove Array.Copy and set buffer offset in asyncReceiveEvent
                        //too bad i've not acomplished this yet some really weird shit is happening then
                        int writeOffset = stream.Write(e.Buffer, 0, e.BytesTransferred);
                        this.stream.Flush();

                        if (!Handle.ReceiveAsync(asyncReceiveEvent))
                            AsyncSocketCallback(null, this.asyncReceiveEvent);
                    }
                    catch (Exception ex)
                    {
                        /*if (Client.ServerAllowsReconnecting)
                        {
                            Client.Connect(ConnectionState.Reconnecting);
                        }
                        else*/
                        {
                            Client.Disconnect();
                            Client.onException(ex);
                        }
                    }
                    break;
                }
            }
        }

        private unsafe void networkStreamCallback(Network.NetworkStream stream)
        {
            lock (stream)
            {
                bool DataAvailable = true;
                while (DataAvailable)
                {
                    switch (this.stream.ReceiveState)
                    {
                        case ReceiveType.Header:
                        {
                            if (stream.CanRead(HEADER_SIZE))
                            {
                                //if (ProcessSpeed == ReceivePerformance.Safe)
                                {
                                    byte[] headerData = new byte[HEADER_SIZE];
                                    if (stream.Read(ref headerData, 0, headerData.Length) > 0)
                                    {
                                        //wopEncryption.Decrypt(header, 0, HEADER_SIZE);
                                        stream.NetworkPayload.Header = new PacketHeader(headerData, 0, this);

                                        if (!DPI.Inspect(headerData, stream.NetworkPayload.Header))
                                        {
                                            Client.Handle.Close();
                                            return;
                                        }
                                        this.stream.ReceiveState = ReceiveType.Payload;
                                    }
                                }
                                /*else if (ProcessSpeed == ReceivePerformance.Unsafe)
                                {
                                    wopEncryption.Decrypt(stream.Buffer, stream.Position, HEADER_SIZE);
                                    stream.NetworkPayload.PacketSize = stream.Buffer[stream.Position] | stream.Buffer[stream.Position + 1] << 8 | stream.Buffer[stream.Position + 2] << 16;
                                    stream.NetworkPayload.isCompressed = PacketOption.Compression == ((PacketOption)stream.Buffer[3] & PacketOption.Compression);
                                    stream.NetworkPayload.isCached = PacketOption.Cache == ((PacketOption)stream.Buffer[3] & PacketOption.Cache);
                                    stream.NetworkPayload.packetId = (PacketId)stream.Buffer[stream.Position + 4];
                                    stream.NetworkPayload.MessageId = BitConverter.ToUInt32(stream.Buffer, stream.Position + 7);
                                    stream.NetworkPayload.PluginId = BitConverter.ToUInt64(stream.Buffer, stream.Position + 11);
                                    this.stream.ReceiveState = ReceiveType.Payload;
                                    stream.Position += Connection.HEADER_SIZE;
                                }*/
                            }
                            else
                            {
                                DataAvailable = false;
                            }
                            break;
                        }
                        case ReceiveType.Payload:
                        {
                            if (stream.CanRead(stream.NetworkPayload.Header.PacketSize))
                            {
                                int receivedSize = stream.NetworkPayload.Header.PacketSize;
                                uint packetSize = (uint)stream.NetworkPayload.Header.PacketSize;
                                byte[] payload = stream.Buffer;
                                uint offset = (uint)stream.Position;
                                PacketHeader header = stream.NetworkPayload.Header;
                                IPlugin plugin = null;

                                if (stream.NetworkPayload.Header.PacketID == PacketId.PluginPacket)
                                {
                                    plugin = pluginSystem.GetPlugin(stream.NetworkPayload.Header.PluginId);

                                    if (plugin == null)
                                        throw new Exception("Plugin not found");
                                }

                                if (Client.Certificate != null)
                                {
                                    switch (Client.Certificate.Checksum)
                                    {
                                        case ChecksumHash.CRC32:
                                        {
                                            CRC32 hash = new CRC32();
                                            uint Hash = BitConverter.ToUInt32(hash.ComputeHash(payload, (int)offset, (int)packetSize), 0);

                                            if (stream.NetworkPayload.Header.Hash != Hash)
                                            {

                                            }
                                            break;
                                        }
                                    }
                                }

                                //decrypt, decompress, de-cache the data we received
                                if (plugin != null && plugin.UseOwnProtection)
                                {
                                    payload = plugin.protection.RemoveProtection(payload, ref offset, ref packetSize, ref stream.NetworkPayload.Header);
                                }
                                else
                                {
                                    payload = protection.RemoveProtection(payload, ref offset, ref packetSize, ref stream.NetworkPayload.Header);
                                }


                                /*
                                if (stream.NetworkPayload.isCached)
                                {
                                    payload = ReceiveCache.DeCache(payload, offset, packetSize);
                                    offset = 0;
                                    packetSize = payload.Length;
                                }*/

                                IMessage message = null;
                                try
                                {
                                    message = messageHandler.HandleMessage(new PayloadReader(payload) { Offset = (int)offset }, stream.NetworkPayload.Header.MessageId);

                                    if (message != null)
                                    {
                                        message.RawSize = stream.NetworkPayload.Header.PacketSize;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Client.onException(ex);
                                    continue;
                                }

                                /*if(ProcessSpeed == ReceivePerformance.Unsafe)
                                {
                                    if(!MovedPayload && plugin != null && (plugin.UseOwnSystem))
                                    {
                                        //payload is not moved from memory and plugin is using his own system
                                        //We'll just copy the memory...
                                        payload = new byte[packetSize];
                                        fixed (byte* dataPtr = payload, streamPtr = stream.Buffer)
                                        {
                                            NativeMethods.memcpy(dataPtr, streamPtr, (uint)packetSize);
                                        }
                                    }
                                }*/

                                switch (stream.NetworkPayload.Header.PacketID)
                                {
                                    case PacketId.PacketQueue:
                                    {
                                        PacketTaskQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.ChannelPayload:
                                    {
                                        ChannelPayloadQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.CloseChannel:
                                    {
                                        CloseChannelQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.Disconnected:
                                    {
                                        DisconnectedQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.KeepAlive:
                                    {
                                        KeepAliveQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.OpenChannel:
                                    {
                                        OpenChannelQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.OpenChannelResponse:
                                    {
                                        OpenChannelResponseQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.Payload:
                                    {
                                        PayloadQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.PluginPacket:
                                    {
                                        PluginDataQueue.Enqueue(new PluginRecvInfo(plugin, message, payload));
                                        break;
                                    }
                                }

                                this.stream.ReceiveState = ReceiveType.Header;
                                stream.Position += receivedSize;
                                payload = null;
                            }
                            else
                            {
                                DataAvailable = false;
                            }
                            break;
                        }
                    }
                }
            }
        }

        private void onKeepAliveQueue(IMessage message)
        {
            this.KeepAliveSW = Stopwatch.StartNew();
            Client.onKeepAlive();
        }
        private void onChannelPayloadQueue(IMessage message)
        {
            MsgChannelPayload msg = message as MsgChannelPayload;
            if ((msg = message as MsgChannelPayload) != null)
                msg.ProcessPayload(Client);
        }
        private void onCloseChannelQueue(IMessage message)
        {
            MsgCloseChannel msg = message as MsgCloseChannel;
            if ((msg = message as MsgCloseChannel) != null)
                msg.ProcessPayload(Client);
        }
        private void onDisconnectedQueue(IMessage message)
        {
            MsgDisconnected msg = message as MsgDisconnected;
            if ((msg = message as MsgDisconnected) != null)
                msg.ProcessPayload(Client);
        }
        private void onOpenChannelQueue(IMessage message)
        {
            MsgOpenChannel msg = message as MsgOpenChannel;
            if ((msg = message as MsgOpenChannel) != null)
                msg.ProcessPayload(Client);
        }
        private void onOpenChannelResponseQueue(IMessage message)
        {
            MsgOpenChannelResponse msg = message as MsgOpenChannelResponse;
            if ((msg = message as MsgOpenChannelResponse) != null)
                msg.ProcessPayload(Client);
        }
        private void onPluginDataQueue(PluginRecvInfo pluginInfo)
        {
            if (pluginInfo.Plugin.AllowPluginHooks() && pluginInfo.Plugin.Hooks.Count > 0)
            {
                bool Continue = true;
                foreach (IPluginHook hook in pluginInfo.Plugin.Hooks)
                {
                    IMessage message = pluginInfo.message;
                    if (!hook.onReceiveMessage(ref message))
                        Continue = false;
                    pluginInfo.message = message;
                }
                if (!Continue)
                    return;
            }
            pluginInfo.Plugin.onReceiveMessage(pluginInfo.message);
        }
        private void onPacketTaskQueue(IMessage message)
        {
            /*PayloadReader pr = new PayloadReader(payload);
            while(pr.Offset < payload.Length)
            {
                PacketId packetId = (PacketId)pr.ReadByte();
                byte Duplicates = pr.ReadByte();
                byte[] data = pr.ReadBytes(pr.ReadThreeByteInteger());

                if(packetId != PacketId.Payload && packetId != PacketId.ChannelPayload)
                {
                    //um... wat ?
                    return;
                }

                for(; Duplicates > 0; Duplicates--)
                {
                    switch(packetId)
                    {
                        case PacketId.Payload:
                        {
                            try
                            {
                                if(DPI.Inspect(data, false))
                                {
                                    if(client.MultiThreadProcessing)
                                    {
                                        ThreadPool.QueueUserWorkItem((object o) => client.onReceiveData(data, 0, data.Length));
                                    }
                                    else
                                    {
                                        client.onReceiveData(data, 0, data.Length);
                                    }
                                }
                            }
                            catch(Exception ex)
                            {
                                client.onException(ex);
                            }
                            break;
                        }
                        case PacketId.ChannelPayload:
                        {
                            //new R_ChannelPayload(data) { RawSize = data.Length }.ReadPayload(this);
                            break;
                        }
                    }
                }
            }*/
        }

        private void onPayloadQueue(IMessage message)
        {
            try
            {
                //if (DPI.Inspect(packetInfo.Data, false))
                {
                    if (Client.MultiThreadProcessing)
                    {
                        ThreadPool.QueueUserWorkItem((object o) =>
                        {
                            IMessage msg = o as IMessage;
                            Client.onReceiveMessage(msg);
                        }, message);
                    }
                    else
                    {
                        Client.onReceiveMessage(message);
                    }
                }
            }
            catch (Exception ex)
            {
                Client.onException(ex);
            }
        }

        internal void SendPacketQueue(byte[] data, int offset, int length, PacketId packetId)
        {
            lock (Client)
            {
                Array.Copy(data, offset, data, 0, length);
                Array.Resize(ref data, length);
                packetQueue.QueuePacket(data, packetId);
            }
        }

        internal void SendPacket(IMessage message, PacketId packetId, bool compress = true, bool cache = true)
        {
            lock (Client)
            {
                //clear the packet queue by sending all the stuff that had to be sended
                packetQueue.CleanQueue();
                SendPayload(message, packetId, null, compress, cache);
            }
        }

        internal unsafe void SendPayload(IMessage message, PacketId packetId, IPlugin plugin = null, bool compress = true, bool cache = true, PluginHeaderCallback HeaderCallback = null)
        {
            NetworkPayloadWriter temp = message.WritePacket(message, this, plugin, HeaderCallback);
            message.RawSize = temp.Length - HEADER_SIZE;
            SendPayload(temp, messageHandler.GetMessageId(message.GetType()), packetId, plugin, compress, cache);
        }

        private unsafe void SendPayload(NetworkPayloadWriter npw, uint MessageId, PacketId packetId, IPlugin plugin = null, bool compress = true, bool cache = true)
        {
            lock (ClientSendLock)
            {
                cache = false;

                PacketHeader header = new PacketHeader(this);
                uint offset = (uint)HEADER_SIZE;
                uint PayloadLength = (uint)npw.PayloadSize;
                byte[] payload = npw.GetBuffer();

                //apply the encryption(s), compression(s) and cache
                /*if(plugin != null)
                    plugin.protection.ApplyProtection(npw.GetBuffer(), offset, ref length, ref header);
                else*/
                payload = protection.ApplyProtection(payload, offset, ref PayloadLength, ref header);

                header.PacketSize = (int)PayloadLength;
                header.PacketID = packetId;
                
                if (packetId == PacketId.PluginPacket)
                {
                    header.isPluginPacket = true;
                    if (plugin != null)
                    {
                        header.PluginId = plugin.PluginId;
                    }
                }

                header.CurPacketId = CurPacketId;
                CurPacketId++;
                header.MessageId = MessageId;
                npw.vStream.Position = 0;
                header.WriteHeader(payload, 0, (int)PayloadLength, npw);
                //npw.WriteBytes(payload, 0, (int)PayloadLength);

                //encrypt the header
                /*wopEncryption.Encrypt(temp, 0, HEADER_SIZE);
                if (this.EncryptionType == EncryptionType.Wop)
                {
                    wopEncryption.Encrypt(temp, HEADER_SIZE, npw.Length);
                }
                else if (this.EncryptionType == EncryptionType.UnsafeXor)
                {
                    unsafeXorEncryption.Encrypt(ref temp, HEADER_SIZE, npw.Length);
                }*/

                try
                {
                    this.Handle.Send(npw.GetBuffer(), (int)PayloadLength + HEADER_SIZE, SocketFlags.None);
                    BytesOut += (ulong)(PayloadLength + HEADER_SIZE);
                }
                catch { }
            }
        }

        internal SyncObject Receive(ReceiveCallback callback)
        {
            lock (Handle)
            {
                if (callback == null)
                    throw new ArgumentNullException("callback");

                if (!Connected)
                    return null;

                SyncObject syncObject = new SyncObject(this);
                NetworkPayload networkPayload = new NetworkPayload(this, syncObject, callback);
                SocketError error = SocketError.AccessDenied;
                Handle.BeginReceive(networkPayload.Payload, 0, (int)networkPayload.PacketSize, SocketFlags.None, out error, ReceivePayloadCallback, networkPayload);
                return syncObject;
            }
        }

        private void ReceivePayloadCallback(IAsyncResult ar)
        {
            NetworkPayload networkPayload = (NetworkPayload)ar.AsyncState;
            SocketError error = SocketError.AccessDenied;
            int received = 0;

            try
            {
                //even tho there is "out error" it can still throw a error
                received = Handle.EndReceive(ar, out error);
            }
            catch { }

            if (received <= 0 || error != SocketError.Success)
            {
                Client.Disconnect();
                return;
            }

            BytesIn += (ulong)received;
            this.LastPacketSW = Stopwatch.StartNew();

            networkPayload.WriteOffset += (uint)received;
            if (networkPayload.WriteOffset == networkPayload.PacketSize && networkPayload.ReceivedHeader)
            {
                /*if (this.EncryptionType == EncryptionType.Wop)
                    networkPayload.Payload = wopEncryption.Decrypt(networkPayload.Payload, 0, networkPayload.Payload.Length);
                else if (this.EncryptionType == EncryptionType.AES)
                    networkPayload.Payload = aesEncryption.Decrypt(networkPayload.Payload, 0, networkPayload.Payload.Length);
                else if (this.EncryptionType == EncryptionType.UnsafeXor)
                    networkPayload.Payload = unsafeXorEncryption.Decrypt(networkPayload.Payload, 0, networkPayload.Payload.Length);
                else
                {

                }

                if (networkPayload.isCompressed)
                {
                    if (this.CompressionType == CompressionType.QuickLZ)
                    {
                        networkPayload.Payload = quickLZ.decompress(networkPayload.Payload, 0);
                    }
                    else if (this.CompressionType == CompressionType.LZ4)
                    {
                        networkPayload.Payload = this.Lz4Decompressor.Decompress(networkPayload.Payload);
                    }
                    else if (this.CompressionType == CompressionType.LZMA)
                    {
                        using (MemoryStream outStream = new MemoryStream())
                        {
                            lzmaCompressor.DecompressLZMA(new MemoryStream(networkPayload.Payload), outStream);
                            networkPayload.Payload = outStream.ToArray();
                        }
                    }
                    else if (this.CompressionType == CompressionType.Gzip)
                    {
                        using (MemoryStream outStream = new MemoryStream())
                        {
                            using (GZipStream gs = new GZipStream(outStream, CompressionMode.Decompress))
                            {
                                gs.Write(networkPayload.Payload, 3, networkPayload.Payload.Length-3);
                                networkPayload.Payload = outStream.ToArray();

                                int DecompressedSize = networkPayload.Payload[0] | networkPayload.Payload[1] << 8 | networkPayload.Payload[2] << 16;
                                byte[] decompressed = new byte[DecompressedSize];
                                int readed = gs.Read(decompressed, 0, decompressed.Length);
                                networkPayload.Payload = decompressed;
                            }
                        }
                    }
                }

                if (networkPayload.isCached)
                {
                    networkPayload.Payload = ReceiveCache.DeCache(networkPayload.Payload, 0, networkPayload.Payload.Length);
                }*/


                //decrypt, decompress, de-cache the data we received
                uint Offset = 0;
                uint length = (uint)networkPayload.Payload.Length;
                networkPayload.Payload = protection.RemoveProtection(networkPayload.Payload, ref Offset, ref length, ref networkPayload.Header);


                if (!DPI.Inspect(networkPayload.Payload, null))
                {
                    Client.Disconnect();
                    return;
                }

                IMessage message = null;

                try
                {
                    message = messageHandler.HandleMessage(new PayloadReader(networkPayload.Payload), networkPayload.Header.MessageId);
                }
                catch
                {
                    
                }

                networkPayload.syncObject.Value = networkPayload.Callback(message);
                networkPayload.syncObject.Pulse();
                return; //no need to read futher
            }

            if (!networkPayload.ReceivedHeader && networkPayload.ReceivedPacket)
            {
                try
                {
                    networkPayload.ReceivedHeader = true;
                    //wopEncryption.Decrypt(networkPayload.Payload, 0, HEADER_SIZE);
                    networkPayload.Header = new PacketHeader(networkPayload.Payload, 0, this);

                    if (!DPI.Inspect(networkPayload.Payload, networkPayload.Header))
                    {
                        Client.Disconnect();
                        return;
                    }

                    networkPayload.PacketSize = networkPayload.Header.PacketSize;
                    networkPayload.Payload = new byte[networkPayload.Header.PacketSize];
                    networkPayload.WriteOffset = 0; //just reset offset for reading
                }
                catch
                {
                    Client.Disconnect();
                    return;
                }
            }

            if (networkPayload.WriteOffset != networkPayload.PacketSize)
            {
                Handle.BeginReceive(networkPayload.Payload, (int)networkPayload.WriteOffset, (int)(networkPayload.PacketSize - networkPayload.WriteOffset), SocketFlags.None, out error, ReceivePayloadCallback, networkPayload);
            }
        }

        internal void ReConnect()
        {

        }
    }
}