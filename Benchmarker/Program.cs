using SecureSocketProtocol2;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace Benchmarker
{
    class Program
    {
        private class ConnectionInfo
        {
            public int CreatedConnections;
            public Stopwatch ConnectionSW = Stopwatch.StartNew();
        }


        static List<Client> Clients = new List<Client>();
        const int ThreadCount = 8;

        static void Main(string[] args)
        {
            List<Thread> threads = new List<Thread>();
            List<ConnectionInfo> info = new List<ConnectionInfo>();

            for(int i = 0; i < ThreadCount; i++)
            {
                info.Add(new ConnectionInfo());
                Thread thread = new Thread(new ParameterizedThreadStart(CreateConnectionThread));
                thread.Start(info[info.Count-1]);
                threads.Add(thread);
            }

            int PrevCount = Clients.Count;
            while (true)
            {
                Console.Clear();
                Console.WriteLine("Clients connected: " + Clients.Count);
                Console.WriteLine("Creating new connections " + (Clients.Count - PrevCount) + " per second");
                PrevCount = Clients.Count;

                for (int i = 0; i < info.Count; i++)
                {
                    ConnectionInfo inf = info[i];
                    Console.WriteLine("[Thread" + i + "] Connections created: " + inf.CreatedConnections + ", Trying to connect time: " + inf.ConnectionSW.Elapsed);
                }
                Thread.Sleep(1000);
            }
        }

        static void CreateConnectionThread(object o)
        {
            ConnectionInfo info = (ConnectionInfo)o;
            while(true)
            {
                Client client = new Client();
                info.CreatedConnections++;
                info.ConnectionSW = Stopwatch.StartNew();

                lock (Clients)
                {
                    Clients.Add(client);
                }
            }
        }
    }

    public class Client : SSPClient
    {
        public Client()
            : base("127.0.0.1", 539, typeof(ClientChannel), new object[0], new byte[]
            { //private key, can be any size you want
                80, 118, 131, 114, 195, 224, 157, 246, 141, 113,
                186, 243, 77, 151, 247, 84, 70, 172, 112, 115,
                112, 110, 91, 212, 159, 147, 180, 188, 143, 251,
                218, 155
            }, new Stream[]
            {//key files
                //new FileStream(@"C:\Users\Anguis\Desktop\lel.png", FileMode.Open, FileAccess.Read, FileShare.Read)
            },//login
               "Dergan", "Hunter:)")
        {

        }

        public override void onReceiveMessage(SecureSocketProtocol2.Network.Messages.IMessage message)
        {

        }

        public override void onClientConnect()
        {

        }

        public override void onValidatingComplete()
        {

        }

        public override void onDisconnect()
        {

        }

        public override void onDeepPacketInspection(SecureSocketProtocol2.Network.Messages.IMessage message)
        {

        }

        public override void onKeepAlive()
        {

        }

        public override void onException(Exception ex)
        {

        }

        public override void onReconnect()
        {

        }

        public override void onNewChannelOpen(SecureSocketProtocol2.Network.Channel channel)
        {

        }

        public override void onRegisterMessages(SecureSocketProtocol2.Network.Messages.MessageHandler messageHandler)
        {

        }

        public override bool onVerifyCertificate(CertInfo certificate)
        {
            return true;
        }

        public override void onAddProtection(SecureSocketProtocol2.Network.Protections.Protection protection)
        {

        }

        public override uint HeaderTrashCount
        {
            get { return 5; }
        }

        public override SecureSocketProtocol2.Plugin.IPlugin[] onGetPlugins()
        {
            return new IPlugin[]
            {

            };
        }

        public override uint PrivateKeyOffset
        {
            get { return 45532; }
        }

        public override bool onAuthentication(string Username, string Password)
        {
            return true;
        }

        public override void onAuthenticated()
        {

        }

        public override void onReceiveUdpMessage(IMessage message)
        {

        }
    }

    public class ClientChannel : Channel
    {
        public override void onChannelOpen()
        {

        }

        public override void onChannelClosed()
        {

        }

        public override void onReceiveMessage(SecureSocketProtocol2.Network.Messages.IMessage message)
        {

        }
    }
}