using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Client
{
    class TestChannel : Channel
    {
        int Received = 0;
        int PacketsPerSec = 0;
        Stopwatch speedSW = Stopwatch.StartNew();

        public TestChannel()
            : base()
        {

        }

        public override void onChannelOpen()
        {
            //Console.WriteLine("Test channel has being open'd");
        }

        public override void onChannelClosed()
        {
            //Console.WriteLine("Test channel has being closed");
        }

        public override void onReceiveMessage(IMessage message)
        {
            PacketsPerSec++;
            Received += message.RawSize;

            if(speedSW.ElapsedMilliseconds >= 1000)
            {
                Console.WriteLine("[channel] last size: " + message.RawSize + ", Packet /sec:" + PacketsPerSec + ", data /sec:" + Received + " [" + Math.Round(((float)Received / 1024F) / 1024F, 2) + "MBps]");
                PacketsPerSec = 0;
                Received = 0;
                speedSW = Stopwatch.StartNew();
            }
        }
    }
}
