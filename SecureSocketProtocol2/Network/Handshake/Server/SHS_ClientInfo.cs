using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using System;
using System.Collections.Generic;
using System.Text;
using SecureSocketProtocol2.Network.Messages;

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
                    HandshakeType.ReceiveMessage,
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
                    HandshakeType.SendMessage,
                    HandshakeType.ReceiveMessage
                };
            }
        }

        public override bool onHandshake()
        {
            SyncObject syncObject = null;
            if (!(syncObject = base.ReceiveMessage((IMessage message) =>
            {
                MsgClientSettings mcs = message as MsgClientSettings;

                if (mcs != null)
                {
                    Client.PeersAllowed = mcs.AllowPeers;
                    Client.ChannelsAllowed = mcs.AllowChannels;
                    return true;
                }
                return false;
            })).Wait<bool>(false, 30000))
            {
                Client.Disconnect(DisconnectReason.TimeOut);
                Client.onException(new Exception("Handshake went wrong, CHS_ClientInfo"), ErrorType.Core);
                if (syncObject.TimedOut)
                    throw new TimeoutException(OutOfSyncMessage);
                throw new Exception("Failed to retrieve the Client Settings");
            }

            if (serverProperties.AllowUdp)
            {
                Client.UdpHandshakeCode = new byte[50];
                Client.random.NextBytes(Client.UdpHandshakeCode);
            }

            Client.Token = new RandomDecimal(DateTime.Now.Millisecond).NextDecimal();
            Client.VirtualIP = Client.Server.GetNewVirtualIp();
            base.SendMessage(new MsgClientInfo(Client.ClientId, Client.UdpHandshakeCode, Client.Token, Client.VirtualIP));
            return true;
        }
    }
}