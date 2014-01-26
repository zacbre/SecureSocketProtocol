using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    internal class SHS_UDP : Handshake
    {
        private ServerProperties serverProperties;
        private Socket UdpClient;
        public SHS_UDP(SSPClient client, ServerProperties serverProperties, Socket UdpClient)
            : base(client)
        {
            this.serverProperties = serverProperties;
            this.UdpClient = UdpClient;
        }

        public override HandshakeType[] ServerTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.SendMessage
                };
            }
        }

        public override HandshakeType[] ClientTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.ReceiveMessage
                };
            }
        }

        public override bool onHandshake()
        {
            if (serverProperties.AllowUdp)
            {
                //let's process the UDP protocol
                Client.UdpHandle = UdpClient;
                Client.UdpSyncObject = new SyncObject(Client.Connection);

                if (!Client.UdpSyncObject.Wait<bool>(false, 30000))
                {
                    Client.Disconnect();
                    return false;
                }
            }
            Client.MessageHandler.ResetMessages();
            return true;
        }
    }
}