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
        }

        public bool DoHandshake()
        {
            foreach (Handshake handShake in HandShakes)
            {
                Console.WriteLine(handShake.GetType().Name);
                if (!handShake.DoHandshake())
                {
                    Console.WriteLine(handShake.GetType().Name + ", FAILED");
                    Client.Disconnect();
                    return false;
                }
            }
            return true;
        }
    }
}