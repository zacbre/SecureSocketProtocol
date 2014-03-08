using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    internal class PacketQueue
    {
        public const int MaxMemoryUsageMultiplier = 5; //only affects the sender
        public int MaxPacketQueueSize { get { return Connection.MAX_PAYLOAD * MaxMemoryUsageMultiplier; } }
        public int TimeOut { get { return 250; } }
        private Queue<PacketQueueInfo> packetQueue = new Queue<PacketQueueInfo>();
        private bool threadRunning = false;
        private long sizeCounter = 0;
        private Connection conn;
        private AutoResetEvent arSizeUpdate = new AutoResetEvent(false);
        private int MaxProcessingTime = 500;
        private object AddQueueLock = new object();

        public PacketQueue(Connection c)
        {
            this.conn = c;
        }

        public void CleanQueue()
        {
            lock(packetQueue)
            {
                while (packetQueue.Count > 0)
                    SendQueue();
            }
        }

        public unsafe void QueuePacket(IMessage message, PacketId packetId, IPlugin plugin, Channel channel)
        {
            lock (AddQueueLock)
            {
                if (sizeCounter > MaxPacketQueueSize)
                {
                    while (packetQueue.Count > 0)
                        SendQueue();
                }

                NetworkPayloadWriter temp = message.WritePacket(message, conn);
                message.RawSize = temp.Length - conn.HEADER_SIZE;
                byte[] packet = temp.GetPayload();

                lock (packetQueue)
                {
                    packetQueue.Enqueue(new PacketQueueInfo(packet, packetId, plugin, channel, conn.messageHandler.GetMessageId(message.GetType())));
                    sizeCounter += packet.Length;
                }

                if (!threadRunning)
                {
                    threadRunning = true;
                    ThreadPool.QueueUserWorkItem((object obj) => WorkerThread());
                }
                arSizeUpdate.Set();
            }
        }

        private void WorkerThread()
        {
            while (packetQueue.Count != 0)
            {
                if (!arSizeUpdate.WaitOne(TimeOut))
                    SendQueue();
                if (MaxPacketQueueSize <= sizeCounter)
                    SendQueue();
            }
            threadRunning = false;
        }

        private unsafe void SendQueue()
        {
            lock (packetQueue)
            {
                if (packetQueue.Count == 0)
                    return;

                PayloadWriter pw = new PayloadWriter();
                PacketQueueInfo currentData = null;
                PacketQueueInfo compareBuffer = null;
                Stopwatch sw = Stopwatch.StartNew();

                while (packetQueue.Count > 0 && sw.ElapsedMilliseconds < this.MaxProcessingTime)
                {
                    while (packetQueue.Count > 0)
                    {
                        if (currentData == null)
                        {
                            currentData = packetQueue.Dequeue();
                            sizeCounter -= currentData.Payload.Length;
                            continue;
                        }

                        if (currentData.Duplicates == 255)
                            break;

                        compareBuffer = packetQueue.Peek();

                        if (compareBuffer.Payload.Length == currentData.Payload.Length || compareBuffer.MessageId != currentData.MessageId)
                        {
                            fixed (byte* ptr1 = currentData.Payload, ptr2 = compareBuffer.Payload)
                            {
                                if (NativeMethods.memcmp(ptr1, ptr2, (uint)currentData.Payload.Length) == 0)
                                {
                                    currentData.Duplicates++;
                                    sizeCounter -= compareBuffer.Payload.Length;
                                    packetQueue.Dequeue();
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                        else
                        {
                            break;
                        }
                    }

                    pw.WriteBytes(currentData.ToByteArray());
                    currentData = null;
                    compareBuffer = null;

                    if (pw.Length > 65535)
                        break;
                }

                conn.SendPayload(new MsgPacketQueue(pw.ToByteArray()), PacketId.PacketQueue);
                pw = null;
                sw.Stop();
            }
        }

        private class PacketQueueInfo : IDisposable
        {
            public byte[] Payload;
            public PacketId packetId;
            public byte Duplicates = 1;
            public IPlugin plugin;
            public Channel channel;
            public uint MessageId;

            public PacketQueueInfo(byte[] Payload, PacketId packetId, IPlugin plugin, Channel channel, uint MessageId)
            {
                this.Payload = Payload;
                this.packetId = packetId;
                this.plugin = plugin;
                this.channel = channel;
                this.MessageId = MessageId;
            }

            public byte[] ToByteArray()
            {
                PayloadWriter pw = new PayloadWriter();
                pw.WriteByte((byte)packetId);
                pw.WriteByte(Duplicates);
                pw.WriteBool(plugin != null);
                if (plugin != null)
                    pw.WriteULong(plugin.PluginId);

                pw.WriteBool(channel != null);
                if (channel != null)
                    pw.WriteUInteger(channel.ConnectionId);

                pw.WriteUInteger(MessageId);

                pw.WriteThreeByteInteger(Payload.Length);
                pw.WriteBytes(Payload);
                return pw.ToByteArray();
            }

            public void Dispose()
            {
                Payload = null;
                Duplicates = 0;
            }
        }
    }
}