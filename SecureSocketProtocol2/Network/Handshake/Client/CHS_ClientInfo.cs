using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_ClientInfo : Handshake
    {
        public CHS_ClientInfo(SSPClient client)
            : base(client)
        {

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
            SyncObject syncObject = null;
            if (!(syncObject = base.ReceiveMessage((IMessage message) =>
            {
                MsgClientInfo mci = message as MsgClientInfo;

                if (mci != null)
                {
                    Client.ClientId = mci.ClientId;
                    Client.Token = mci.Token;

                    if (Client.UseUDP)
                    {
                        Client.UdpHandshakeCode = mci.UdpHandshakeCode;
                    }
                    return true;
                }
                return false;
            })).Wait<bool>(false, 30000))
            {
                Client.Disconnect(DisconnectReason.TimeOut);
                Client.onException(new Exception("Handshake went wrong, CHS_ClientInfo"), ErrorType.Core);
                if (syncObject.TimedOut)
                    throw new TimeoutException(OutOfSyncMessage);
                throw new Exception("Failed to retrieve the Client Id");
            }
            return true;
        }
    }
}