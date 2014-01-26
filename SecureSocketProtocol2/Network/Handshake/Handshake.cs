using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake
{
    internal abstract class Handshake
    {
        internal const string TimeOutMessage = "A timeout occured, this means the server did not respond for ~30 seconds";
        internal const string OutOfSyncMessage = "Handshake failed to complete, out-of-sync";
        public abstract bool onHandshake();
        public abstract HandshakeType[] ServerTypes { get; }
        public abstract HandshakeType[] ClientTypes { get; }
        public SSPClient Client { get; private set; }
        private int ServerTypeIndex = 0;
        private int ClientTypeIndex = 0;

        public HandshakeType CurrentServerAction
        {
            get
            {
                if (ServerTypeIndex >= ServerTypes.Length)
                    return HandshakeType.Unknown;
                return ServerTypes[ServerTypeIndex];
            }
        }
        public HandshakeType CurrentClientAction
        {
            get
            {
                if (ClientTypeIndex >= ClientTypes.Length)
                    return HandshakeType.Unknown;
                return ClientTypes[ClientTypeIndex];
            }
        }

        public bool CanServerSendMessage { get { return CurrentServerAction == HandshakeType.SendMessage; } }
        public bool CanClientSendMessage { get { return CurrentClientAction == HandshakeType.SendMessage; } }
        public bool CanServerReceiveMessage { get { return CurrentServerAction == HandshakeType.ReceiveMessage; } }
        public bool CanClientReceiveMessage { get { return CurrentClientAction == HandshakeType.ReceiveMessage; } }

        public Handshake(SSPClient client)
        {
            this.Client = client;
        }

        public void SendMessage(IMessage message)
        {
            if (Client.PeerSide == PeerSide.Client && !CanClientSendMessage)
                throw new Exception("The client cannot send a message at this time, check the agreed handshake");
            else if (Client.PeerSide == PeerSide.Server && !CanServerSendMessage)
                throw new Exception("The server cannot send a message at this time, check the agreed handshake");

            Client.Connection.SendPacket(message, PacketId.Unknown);

            if (Client.PeerSide == PeerSide.Client)
                ClientTypeIndex++;
            else if (Client.PeerSide == PeerSide.Server)
                ServerTypeIndex++;
        }

        public IMessage ReceiveMessage(uint TimeOut = 30000)
        {
            if (Client.PeerSide == PeerSide.Client && !CanClientReceiveMessage)
                throw new Exception("The client cannot receive at this time, check the agreed handshake");
            else if (Client.PeerSide == PeerSide.Server && !CanServerReceiveMessage)
                throw new Exception("The server cannot receive at this time, check the agreed handshake");

            IMessage retMsg = null;
            if (!Client.Connection.Receive((IMessage message) =>
            {
                retMsg = message;
                if (retMsg != null)
                    return true;
                return false;
            }).Wait<bool>(false, TimeOut))
            {
                Client.Disconnect();
                throw new Exception(TimeOutMessage);
            }

            if (Client.PeerSide == PeerSide.Client)
                ClientTypeIndex++;
            else if (Client.PeerSide == PeerSide.Server)
                ServerTypeIndex++;

            return retMsg;
        }
        public SyncObject ReceiveMessage(ReceiveCallback callback)
        {
            if (Client.PeerSide == PeerSide.Client && !CanClientReceiveMessage)
                throw new Exception("The client cannot receive at this time, check the agreed handshake");
            else if (Client.PeerSide == PeerSide.Server && !CanServerReceiveMessage)
                throw new Exception("The server cannot receive at this time, check the agreed handshake");

            if (Client.PeerSide == PeerSide.Client)
                ClientTypeIndex++;
            else if (Client.PeerSide == PeerSide.Server)
                ServerTypeIndex++;

            return Client.Connection.Receive(callback);
        }

        public bool ValidatePhase_Server()
        {
            Client.Connection.SendPacket(new MsgOk(), PacketId.Unknown);

            if (!Client.Connection.Receive((IMessage message) =>
            {
                MsgOk msgOk = message as MsgOk;
                if (msgOk != null)
                    return true;
                return false;
            }).Wait<bool>(false, 30000))
            {
                return false;
            }

            //tell the client it's ok again so we can move on
            Client.Connection.SendPacket(new MsgOk(), PacketId.Unknown);
            return true;
        }

        public bool ValidatePhase_Client()
        {
            if (!Client.Connection.Receive((IMessage message) =>
            {
                MsgOk msgOk = message as MsgOk;
                if (msgOk != null)
                    return true;
                return false;
            }).Wait<bool>(false, 30000))
            {
                return false;
            }

            Client.Connection.SendPacket(new MsgOk(), PacketId.Unknown);

            if (!Client.Connection.Receive((IMessage message) =>
            {
                MsgOk msgOk = message as MsgOk;
                if (msgOk != null)
                    return true;
                return false;
            }).Wait<bool>(false, 30000))
            {
                return false;
            }
            return true;
        }

        public bool DoHandshake()
        {
            if (!onHandshake())
                throw new Exception(OutOfSyncMessage);

            if (Client.PeerSide == PeerSide.Client)
            {
                if (!ValidatePhase_Client())
                    throw new Exception(OutOfSyncMessage);
            }
            else if (Client.PeerSide == PeerSide.Server)
            {
                if (!ValidatePhase_Server())
                    throw new Exception(OutOfSyncMessage);
            }

            return true;
        }
    }
}