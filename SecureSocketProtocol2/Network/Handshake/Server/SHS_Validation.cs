using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    class SHS_Validation : Handshake
    {
        public SHS_Validation(SSPClient client)
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
            if (!base.ReceiveMessage((IMessage message) =>
            {
                MsgValidation validation = message as MsgValidation;

                if (validation != null)
                {
                    if (validation.ValidationKey.Length != Connection.VALIDATION.Length)
                        return false;

                    unsafe
                    {
                        fixed (byte* ptr = validation.ValidationKey, ptr2 = Connection.VALIDATION)
                        {
                            if (NativeMethods.memcmp(ptr, ptr2, (uint)Connection.VALIDATION.Length) == 0)
                            {
                                base.SendMessage(new MsgValidation(true));
                                return true;
                            }
                        }
                    }
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                Client.Disconnect(DisconnectReason.TimeOut);
                Client.onException(new Exception("Handshake went wrong, SHS_Validation"), ErrorType.Core);
                return false;
            }

            Client.onValidatingComplete();
            return true;
        }
    }
}
