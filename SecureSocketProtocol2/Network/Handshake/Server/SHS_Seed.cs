using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    internal class SHS_Seed : Handshake
    {
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

        public SHS_Seed(SSPClient client)
            : base(client)
        {

        }

        public override bool onHandshake()
        {
            Client.Connection.messageHandler.RegisterMessages(0); //set seed 0 so it generates a new seed
            base.SendMessage(new MsgMessageSeed(Client.Connection.messageHandler.Seed));
            return true;
        }
    }
}
