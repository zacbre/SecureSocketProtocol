using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    internal class SHS_ClientInfo : Handshake
    {
        private ServerProperties serverProperties;
        public SHS_ClientInfo(SSPClient client, ServerProperties serverProperties)
            : base(client)
        {
            this.serverProperties = serverProperties;
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
            Random rnd = new Random(DateTime.Now.Millisecond);
            if (serverProperties.AllowUdp)
            {
                Client.UdpHandshakeCode = new byte[50];
                rnd.NextBytes(Client.UdpHandshakeCode);
            }

            Client.Token = new RandomDecimal(DateTime.Now.Millisecond).NextDecimal();
            base.SendMessage(new MsgClientInfo(Client.ClientId, Client.UdpHandshakeCode, Client.Token));
            return true;
        }
    }
}