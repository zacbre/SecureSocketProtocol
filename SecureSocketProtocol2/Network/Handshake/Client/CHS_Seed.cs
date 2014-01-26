using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_Seed : Handshake
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

        public CHS_Seed(SSPClient client)
            : base(client)
        {

        }

        public override bool onHandshake()
        {
            SyncObject syncObject = null;
            if (!(syncObject = base.ReceiveMessage((IMessage message) =>
            {
                MsgMessageSeed mms = message as MsgMessageSeed;

                if (mms != null)
                {
                    Client.Connection.messageHandler.RegisterMessages(mms.Seed);
                    return true;
                }
                return false;
            })).Wait<bool>(false, 30000))
            {
                Client.Disconnect();
                if (syncObject.TimedOut)
                    throw new TimeoutException(TimeOutMessage);
                throw new Exception("Failed to retrieve the message seed.");
            }

            return true;
        }
    }
}