using SecureSocketProtocol2;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace Benchmarker
{
    class Program
    {
        static List<Client> Clients = new List<Client>();
        const int ThreadCount = 8;
        static void Main(string[] args)
        {
            List<Thread> threads = new List<Thread>();
            for(int i = 0; i < ThreadCount; i++)
            {
                Thread thread = new Thread(new ThreadStart(CreateConnectionThread));
                thread.Start();
                threads.Add(thread);
            }

            while (true)
            {
                Console.WriteLine("Clients connected: " + Clients.Count);
                Thread.Sleep(1000);
            }
        }

        static void CreateConnectionThread()
        {
            while(true)
            {
                Client client = new Client();
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
            {
                80, 118, 131, 114, 195, 224, 157, 246, 141, 113,
                186, 243, 77, 151, 247, 84, 70, 172, 112, 115,
                112, 110, 91, 212, 159, 147, 180, 188, 143, 251,
                218, 155
            })
        {

        }

        public override void onReceiveMessage(SecureSocketProtocol2.Network.Messages.IMessage message)
        {

        }

        public override void onReceiveUdpData(byte[] data, int size)
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
    }

    public class ClientChannel : Channel
    {
        public override void onChannelOpen()
        {

        }

        public override void onChannelClosed()
        {

        }

        public override void onReceiveData(SecureSocketProtocol2.Network.Messages.IMessage message)
        {

        }
    }
}