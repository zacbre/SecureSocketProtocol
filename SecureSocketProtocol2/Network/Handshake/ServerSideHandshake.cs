using SecureSocketProtocol2.Network.Handshake.Server;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake
{
    internal class ServerSideHandshake
    {
        public SSPClient Client { get; private set; }
        private List<Handshake> HandShakes;

        public ServerSideHandshake(SSPClient client, ServerProperties serverProperties, Socket UdpClient, GetClientsDelegate getClientsDelegate, PrivateKeyHandler KeyHandler)
        {
            this.Client = client;
            this.HandShakes = new List<Handshake>();
            this.HandShakes.Add(new SHS_Validation(client));
            this.HandShakes.Add(new SHS_Seed(client));
            this.HandShakes.Add(new SHS_KeyExchange(client, serverProperties, KeyHandler));
            this.HandShakes.Add(new SHS_Authentication(client, serverProperties));
            this.HandShakes.Add(new SHS_TimeSynchronisation(client));
            this.HandShakes.Add(new SHS_ClientInfo(client, serverProperties));
            this.HandShakes.Add(new SHS_UDP(client, serverProperties, UdpClient));
            this.HandShakes.Add(new SHS_Plugins(client, getClientsDelegate));
            this.HandShakes.Add(new SHS_ShareClasses(client));
        }

        public bool DoHandshake()
        {
            foreach (Handshake handShake in HandShakes)
            {
                if (!handShake.DoHandshake())
                {
                    Console.WriteLine(handShake.GetType().Name + ", FAILED");
                    Client.Disconnect(DisconnectReason.HandShakeFailed);
                    return false;
                }
            }

            Client.Connection.Handshaked = true;

            return true;
        }
    }
}
