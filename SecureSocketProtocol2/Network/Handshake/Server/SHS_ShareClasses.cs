using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using SecureSocketProtocol2.Shared.SharedClasses;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    internal class SHS_ShareClasses : Handshake
    {
        public SHS_ShareClasses(SSPClient client)
            : base(client)
        {

        }

        public override bool onHandshake()
        {
            Client.ShareClass("LITECODE_CHANNEL", typeof(SharedChannel), false, 1, Client.Connection);
            Client.ShareClass("SHARED_ROOT", typeof(SharedRoot), false, 1, Client);
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