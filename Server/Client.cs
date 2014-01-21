using SecureSocketProtocol2;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Protections;
using SecureSocketProtocol2.Plugin;
using Server.LiteCode;
using Server.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace Server
{
    public class Client : SSPClient
    {
        ulong Received = 0;
        int PacketsPerSec = 0;
        Stopwatch sw = Stopwatch.StartNew();
        PayloadWriter pw = new PayloadWriter();
        Stopwatch speedSW = Stopwatch.StartNew();

        public Client()
            : base(typeof(TestChannel), new object[0], true)
        {

        }

        public override void onReceiveMessage(IMessage message)
        {
            TestMessage tm = message as TestMessage;
            if (tm != null)
            {
                PacketsPerSec++;
                Received += (ulong)message.RawSize;

                if (speedSW.ElapsedMilliseconds >= 1000)
                {
                    Console.WriteLine("[TCP] last size:" + message.RawSize +
                                      ", pps:" + PacketsPerSec +
                                      ", data /sec:" + Received + " [" + Math.Round(((float)Received / 1024F) / 1024F, 2) + "MBps]" +
                                      ", bit:" + Math.Round(((float)((float)Received * 8F) / 1024F) / 1024F, 2));
                    PacketsPerSec = 0;
                    Received = 0;
                    speedSW = Stopwatch.StartNew();
                }
            }
        }

        public override void onClientConnect()
        {
            Console.WriteLine("Client accepted");
            base.MessageHandler.AddMessage(typeof(TestMessage), "TEST_MESSAGE");
        }

        public override void onValidatingComplete()
        {
            Console.WriteLine("Validating connection...");
        }

        public override void onDisconnect()
        {
            Console.WriteLine("Client disconnected");
        }

        public override void onDeepPacketInspection(IMessage message)
        {
            
        }

        public override void onKeepAlive()
        {
            Console.WriteLine("Received keep-alive");
        }

        public override void onException(Exception ex)
        {

        }

        public override void onReconnect()
        {

        }

        public override void onNewChannelOpen(Channel channel)
        {

        }

        public override void onReceiveUdpMessage(IMessage message)
        {
            PacketsPerSec++;
            Received += (ulong)message.RawSize;

            if (speedSW.ElapsedMilliseconds >= 1000)
            {
                Console.WriteLine("[UDP] last size:" + message.RawSize +
                                  ", Packet /sec:" + PacketsPerSec +
                                  ", data /sec:" + Received + " [" + Math.Round(((float)Received / 1024F) / 1024F, 2) + "MBps]" +
                                  ", bit:" + Math.Round(((float)((float)Received * 8F) / 1024F) / 1024F, 2));
                PacketsPerSec = 0;
                Received = 0;
                speedSW = Stopwatch.StartNew();
            }
        }

        public override void onRegisterMessages(MessageHandler messageHandler)
        {

        }

        public override bool onVerifyCertificate(CertInfo certificate)
        {
            return true;
        }

        public override IPlugin[] onGetPlugins()
        {
            return new IPlugin[]
            {

            };
        }

        public override void onAddProtection(Protection protection)
        {

        }

        public override uint HeaderTrashCount
        {
            get { return 5; }
        }
        public override uint PrivateKeyOffset
        {
            get { return 45532; }
        }

        public override bool onAuthentication(string Username, string Password)
        {
            Console.WriteLine("Authenication, Username:" + Username + ", Password:" + Password);

            if (Username == "Dergan" && Password == "0215C4D7AC62DF61A7ACCAD0E4EDEFC0A2BD4C50D656DA8282069291A1F216977B9AD9D28FCD40B5DE787288E067873847B523A084C169883762F30A5F7EEF89")
                return true;

            return false;
        }

        public override void onAuthenticated()
        {

        }
    }
}