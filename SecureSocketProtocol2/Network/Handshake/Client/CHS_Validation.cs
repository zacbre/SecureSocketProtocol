using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_Validation : Handshake
    {
        public CHS_Validation(SSPClient client)
            : base(client)
        {

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
            base.SendMessage(new MsgValidation(Connection.VALIDATION));
            if (!(syncObject =  base.ReceiveMessage((IMessage message) =>
            {
                MsgValidation validation = message as MsgValidation;
                if (validation != null)
                    return validation.ValidationSuccess;
                return false;
            })).Wait<bool>(false, 30000))
            {
                Client.Disconnect(DisconnectReason.TimeOut);
                Client.onException(new Exception("Handshake went wrong, CHS_Validation"), ErrorType.Core);
                if (syncObject.TimedOut)
                    throw new TimeoutException(TimeOutMessage);
                throw new Exception("Incorrect signature");
            }

            try
            {
                Client.onValidatingComplete();
            }
            catch (Exception ex)
            {
                Client.onException(ex, ErrorType.UserLand);
            }
            return true;
        }
    }
}
