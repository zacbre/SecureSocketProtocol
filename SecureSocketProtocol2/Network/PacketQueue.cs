using SecureSocketProtocol2.Misc;
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
        public int MaxPacketQueueSize { get; set; }
        public int TimeOut { get; set; }
        private Queue<PacketQueueInfo> packetQueue = new Queue<PacketQueueInfo>();
        private bool threadRunning = false;
        private long sizeCounter = 0;
        private Connection conn;
        private AutoResetEvent arSizeUpdate = new AutoResetEvent(false);
        private int MaxProcessingTime;

        public PacketQueue(Connection c)
        {
            MaxPacketQueueSize = 65535;
            TimeOut = 250;
            MaxProcessingTime = 500;
            conn = c;
        }

        public void CleanQueue()
        {
            lock(packetQueue)
            {
                while (packetQueue.Count > 0)
                    SendQueue();
            }
        }

        public unsafe void QueuePacket(byte[] packet, PacketId packetId)
        {
            lock (packetQueue)
            {
                if (sizeCounter > MaxPacketQueueSize)
                {
                    while (packetQueue.Count > 0)
                        SendQueue();
                }

                packetQueue.Enqueue(new PacketQueueInfo(packet, packetId));
                sizeCounter += packet.Length;

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

                        if (compareBuffer.Payload.Length == currentData.Payload.Length || compareBuffer.packetId != currentData.packetId)
                        {
                            fixed (byte* ptr1 = currentData.Payload, ptr2 = compareBuffer.Payload)
                            {
                                if (NativeMethods.memcmp(ptr1, ptr2, (uint)currentData.Payload.Length) == 0)
                                {
                                    currentData.Duplicates++;
                                    sizeCounter -= compareBuffer.Payload.Length;
                                    packetQueue.Dequeue();
                                }
                                else break;
                            }
                        }
                        else break;
                    }

                    pw.WriteBytes(currentData.ToByteArray());
                    currentData = null;
                    compareBuffer = null;

                    if (pw.Length > MaxPacketQueueSize)
                        break;
                }

                //conn.SendPayload(pw.ToByteArray(), 0, pw.Length, PacketId.PacketQueue, true);
                pw = null;
                sw.Stop();
            }
        }

        private class PacketQueueInfo : IDisposable
        {
            public byte[] Payload;
            public PacketId packetId;
            public byte Duplicates = 1;

            public PacketQueueInfo(byte[] Payload, PacketId packetId)
            {
                this.Payload = Payload;
                this.packetId = packetId;
            }

            public byte[] ToByteArray()
            {
                PayloadWriter pw = new PayloadWriter();
                pw.WriteByte((byte)packetId);
                pw.WriteByte(Duplicates);
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