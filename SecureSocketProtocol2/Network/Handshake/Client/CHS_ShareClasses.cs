using SecureSocketProtocol2.Interfaces.Shared;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using SecureSocketProtocol2.Shared.SharedClasses;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_ShareClasses : Handshake
    {
        public CHS_ShareClasses(SSPClient client)
            : base(client)
        {

        }

        public override bool onHandshake()
        {
            base.Client.ShareClass("ROOTSOCKET_CLIENT", typeof(SharedClientRoot), false, 1, Client);
            return true;
        }

        public override HandshakeType[] ServerTypes
        {
            get { return new HandshakeType[0]; }
        }

        public override HandshakeType[] ClientTypes
        {
            get { return new HandshakeType[0]; }
        }
    }
}