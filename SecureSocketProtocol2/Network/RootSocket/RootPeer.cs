using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace SecureSocketProtocol2.Network.RootSocket
{
    public abstract class RootPeer : IClient
    {
        internal const string IpValidationString = @"^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$";

        public abstract void onReceiveMessage(IPeerMessage message);
        public abstract void onClientConnect();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onRegisterMessages(MessageHandler messageHandler);
        public abstract void onException(Exception ex, ErrorType errorType);

        internal decimal ConnectionId;

        private string _virtualIp = null;
        public bool Connected { get; internal set; }

        [NonSerialized]
        internal SSPClient _client;


        public Connection Connection
        {
            get { return _client != null ? _client.Connection : null; }
            set { }
        }

        public SSPClient Client { get { return _client; } }

        internal bool InvokedOnConnect = false;

        public DeepPacketInspection DPI { get; private set; }

        internal uint VirtualIpInt
        {
            get;
            private set;
        }
        public string VirtualIP
        {
            get
            {
                return _virtualIp;
            }
            internal set
            {
                if (!Regex.IsMatch(value, IpValidationString))
                    throw new Exception("Not a valid virtual ip address");
                _virtualIp = value;

                string[] tempStr = value.Split('.');
                byte[] temp = new byte[4];

                for (int i = 0; i < temp.Length; i++)
                    temp[i] = byte.Parse(tempStr[i]);
                VirtualIpInt = BitConverter.ToUInt32(temp, 0);
            }
        }

        //server side
        [NonSerialized]
        internal SSPClient FromClient;
        [NonSerialized]
        internal SSPClient ToClient;

        public RootPeer()
        {
            this.DPI = new DeepPacketInspection();
        }

        public void SendMessage(IPeerMessage message)
        {
            if (!Connected)
                return;

            message.ConnectionId = this.ConnectionId;

            Connection conn = _client.Connection;
            NetworkPayloadWriter temp = message.WritePacket(message, conn);
            message.RawSize = temp.Length - _client.Connection.HEADER_SIZE;

            //apply compression, encryption, masks here

            conn.SendPayload(temp, conn.messageHandler.GetMessageId(message.GetType()), PacketId.RootSocket_Payload, false, null, null, VirtualIpInt);
        }

        public void Disconnect()
        {
            throw new NotImplementedException();
        }
    }
}