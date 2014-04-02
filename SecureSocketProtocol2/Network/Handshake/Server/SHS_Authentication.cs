using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
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
                    MsgAuthentication msgAuth = message as MsgAuthentication;
                    if (msgAuth != null)
                    {
                        //todo: check password if it only contains the character it should have
                        try
                        {
                            bool success = Client.Server.onAuthentication(base.Client, msgAuth.Username, msgAuth.Password);
                            base.SendMessage(new MsgAuthenticationSuccess(success));
                        }
                        catch
                        {
                            base.SendMessage(new MsgAuthenticationSuccess(false));
                        }
                        return true;
                    }
                    else if(message as MsgDummy != null) //the client thinks there is no authentication
                    {
                        return false;
                    }
                    base.SendMessage(new MsgAuthenticationSuccess(false));
                    return false;
                }).Wait<bool>(false, 30000))
                {
                    Client.Disconnect(DisconnectReason.TimeOut);
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
                    Client.Disconnect(DisconnectReason.TimeOut);
                    Client.onException(new Exception("Handshake went wrong, SHS_Authentication"), ErrorType.Core);
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
                Client.onException(ex, ErrorType.UserLand);
            }

            return true;
        }
    }
}