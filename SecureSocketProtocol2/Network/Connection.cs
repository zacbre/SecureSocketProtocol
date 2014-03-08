using SecureSocketProtocol2.Compressions;
using SecureSocketProtocol2.Compressions.LZ4;
using SecureSocketProtocol2.Compressions.LZMA;
using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Channels;
using SecureSocketProtocol2.Network.Messages.TCP.StreamMessages;
using SecureSocketProtocol2.Network.Protections;
using SecureSocketProtocol2.Network.Protections.Cache;
using SecureSocketProtocol2.Network.Protections.Compression;
using SecureSocketProtocol2.Network.Protections.Encryption;
using SecureSocketProtocol2.Plugin;
using SecureSocketProtocol2.Shared;
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
    public sealed partial class Connection
    {
        internal const ReceivePerformance ProcessSpeed = ReceivePerformance.Safe;
        public const int MAX_PAYLOAD = (1024 * 1024) * 5; //5MB is max to be received at once
        public const int MAX_CACHE_SIZE = 1000000; //decrease value to reduce memory usage
        public const int RSA_KEY_SIZE = 2048; //change to a higher value if you feel paranoid
        public const ChecksumHash HandshakeChecksum = ChecksumHash.SHA512;

        internal static readonly byte[] VALIDATION = new byte[]
        {
            151, 221, 126, 222, 126, 142, 126, 208, 107, 209, 212, 218, 228, 167, 158, 252, 105, 147, 185, 178,
            239, 238, 156, 228, 202, 141, 199, 198, 168, 199, 186, 121, 173, 166, 139, 225, 118, 162, 112, 252,
            208, 253, 200, 163, 161, 113, 200, 118, 206, 203, 252, 242, 202, 124, 107, 165, 224, 205, 221, 184,
            153, 161, 215, 146, 246, 166, 247, 135, 247, 107, 223, 160, 126, 193, 150, 248, 187, 219, 141, 211,
            135, 227, 157, 107, 184, 183, 125, 161, 142, 194, 150, 201, 224, 146, 210, 130, 244, 202, 181, 228
        };

        public int HEADER_SIZE
        {
            get
            {
                return (int)(29 + protection.LayerCount + Client.HeaderTrashCount);
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
        private NetworkStream stream;
        private PacketQueue packetQueue;
        public PluginSystem pluginSystem { get; private set; }

        internal Stopwatch KeepAliveSW = new Stopwatch();
        internal Stopwatch LastPacketSW = new Stopwatch();
        internal MessageHandler messageHandler { get; private set; }

        internal SortedList<decimal, SecureStream> Streams;

        //LiteCode
        internal SortedList<decimal, SyncObject> Requests { get; private set; }
        internal SortedList<string, SharedClass> SharedClasses { get; private set; }
        internal SortedList<int, SharedClass> InitializedClasses { get; private set; }

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
            this.ChannelPayloadQueue = new TaskQueue<ChannelRecvInfo>(client, onChannelPayloadQueue, 100);
            this.CloseChannelQueue = new TaskQueue<IMessage>(client, onCloseChannelQueue, 100);
            this.DisconnectedQueue = new TaskQueue<IMessage>(client, onDisconnectedQueue, 100);
            this.OpenChannelQueue = new TaskQueue<IMessage>(client, onOpenChannelQueue, 100);
            this.OpenChannelResponseQueue = new TaskQueue<IMessage>(client, onOpenChannelResponseQueue, 100);
            this.PacketTaskQueue = new TaskQueue<IMessage>(client, onPacketTaskQueue, 10);
            this.PayloadQueue = new TaskQueue<IMessage>(client, onPayloadQueue, 100);
            this.KeepAliveQueue = new TaskQueue<IMessage>(client, onKeepAliveQueue, 10);
            this.PluginDataQueue = new TaskQueue<PluginRecvInfo>(client, onPluginDataQueue, 100);
            this.StreamQueue = new TaskQueue<IMessage>(client, onStreamQueue, 5); //making it 5 on purpose
            this.LiteCodeQueue = new TaskQueue<IMessage>(client, onLiteCodeQueue, 100);
            this.LiteCodeResponseQueue = new TaskQueue<IMessage>(client, onLiteCodeResponseQueue, 100);
            this.LiteCodeDelegateQueue = new TaskQueue<IMessage>(client, onLiteCodeDelegateQueue, 100);

            this.messageHandler = new MessageHandler(0);
            this.pluginSystem = new PluginSystem(client);
            this.protection = new Protection(this);
            this.Streams = new SortedList<decimal, SecureStream>();
            this.Requests = new SortedList<decimal, SyncObject>();
            this.SharedClasses = new SortedList<string, SharedClass>();
            this.InitializedClasses = new SortedList<int, SharedClass>();
        }

        

        internal void ReConnect()
        {

        }
    }
}