using SecureSocketProtocol2;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using Server.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Server
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
            Received += message.RawSize;
            PacketsPerSec++;

            if (speedSW.ElapsedMilliseconds >= 1000)
            {
                Console.WriteLine("speed:" + Math.Round(((float)Received / 1024F) / 1024F, 2) + "MBps, Packets Per Sec: " + PacketsPerSec);
                Received = 0;
                PacketsPerSec = 0;
                speedSW = Stopwatch.StartNew();
            }
        }
    }
}