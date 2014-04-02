using SecureSocketProtocol2.Network.Handshake.Client;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake
{
    internal class ClientSideHandshake
    {
        public SSPClient Client { get; private set; }

        private List<Handshake> HandShakes;

        public ClientSideHandshake(SSPClient client, ClientProperties Properties)
        {
            this.Client = client;
            this.HandShakes = new List<Handshake>();
            this.HandShakes.Add(new CHS_Validation(client));
            this.HandShakes.Add(new CHS_Seed(client));
            this.HandShakes.Add(new CHS_KeyExchange(client));
            this.HandShakes.Add(new CHS_Authentication(client, Properties));
            this.HandShakes.Add(new CHS_TimeSynchronisation(client));
            this.HandShakes.Add(new CHS_ClientInfo(client));
            this.HandShakes.Add(new CHS_UDP(client, Properties));
            this.HandShakes.Add(new CHS_Plugins(client));
            this.HandShakes.Add(new CHS_ShareClasses(client));
        }

        public bool DoHandshake()
        {
            foreach (Handshake handShake in HandShakes)
            {
                if (!handShake.DoHandshake())
                {
                    Client.Disconnect(DisconnectReason.HandShakeFailed);
                    return false;
                }
            }

            if (Client.TimeSync.Year == 1)
            {

            }

            Client.Connection.Handshaked = true;

            return true;
        }
    }
}