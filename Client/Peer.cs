using Client.Messages;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.RootSocket;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Client
{
    public class Peer : RootPeer
    {
        public Peer()
            : base()
        {

        }

        Stopwatch sw = Stopwatch.StartNew();
        ulong Received = 0;
        ulong PacketsPerSec = 0;

        public override void onReceiveMessage(IPeerMessage message)
        {
            Received += (ulong)message.DecompressedRawSize;
            PacketsPerSec++;

            //(message as TestMessage).Stuff = new byte[5];
            //SendMessage(message);

            if (sw.ElapsedMilliseconds >= 1000)
            {
                Console.WriteLine("[Rootsocket] last size: " + message.DecompressedRawSize + ", pps:" + PacketsPerSec + ", data/sec:" + Received + " [" + Math.Round(((float)Received / 1000F) / 1000F, 2) + "MBps] " + (Math.Round((((float)Received / 1000F) / 1000F) / 1000F, 2) * 8F) + "Gbps");
                sw = Stopwatch.StartNew();
                Received = 0;
                PacketsPerSec = 0;
            }
        }

        public override void onClientConnect()
        {
            Console.WriteLine("Peer Connected, Target: " + base.VirtualIP);
        }

        public override void onRegisterMessages(MessageHandler messageHandler)
        {

        }

        public override void onDisconnect(SecureSocketProtocol2.DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, SecureSocketProtocol2.ErrorType errorType)
        {

        }
    }
}