using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    internal class SHS_Authentication : Handshake
    {
        private ServerProperties serverProperties;
        public SHS_Authentication(SSPClient client, ServerProperties serverProperties)
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
            if (serverProperties.UserPassAuthenication)
            {
                if (!base.ReceiveMessage((IMessage message) =>
                {
                    MsgAuthenication msgAuth = message as MsgAuthenication;
                    if (msgAuth != null)
                    {
                        //todo: check password if it only contains the character it should have
                        try
                        {
                            bool success = Client.onAuthentication(msgAuth.Username, msgAuth.Password);
                            base.SendMessage(new MsgAuthenicationSuccess(success));
                        }
                        catch
                        {
                            base.SendMessage(new MsgAuthenicationSuccess(false));
                        }
                        return true;
                    }
                    else if(message as MsgDummy != null) //the client thinks there is no authentication
                    {
                        return false;
                    }
                    base.SendMessage(new MsgAuthenicationSuccess(false));
                    return false;
                }).Wait<bool>(false, 30000))
                {
                    Client.Disconnect();
                    return false;
                }
            }
            else
            {
                //no authentication
                if (!(base.ReceiveMessage((IMessage message) =>
                {
                    if(message as MsgDummy != null)
                        base.SendMessage(new MsgDummy());
                    return message as MsgDummy != null;
                })).Wait<bool>(false, 30000))
                {
                    Client.Disconnect();
                    throw new Exception(OutOfSyncMessage);
                }
            }

            try
            {
                //at this point you could use extra keyfiles or other security measures
                Client.onAuthenticated();
            }
            catch (Exception ex)
            {
                Client.onException(ex);
            }

            return true;
        }
    }
}