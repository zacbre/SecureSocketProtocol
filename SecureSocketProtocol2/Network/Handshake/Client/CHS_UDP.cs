using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.UDP;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_UDP : Handshake
    {
        private ClientProperties Properties;
        public CHS_UDP(SSPClient client, ClientProperties Properties)
            : base(client)
        {
            this.Properties = Properties;
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
            if (Client.UseUDP)
            {
                Client.UdpEndPoint = new IPEndPoint(IPAddress.Parse(Properties.HostIp), Properties.Port);
                Client.UdpHandle = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                SyncObject udpSync = base.ReceiveMessage(onClientUdpHandshake);
                bool UdpSuccess = false;

                //if the 5 tries failed we wasted 25 seconds of our life :(
                for (int i = 0; i < 5; i++)
                {
                    Client.SendUdpMessage(new MsgUdpHandshake(Client.UdpHandshakeCode), UdpPAcketId.Handshake);
                    if (udpSync.Wait<bool>(false, 5000))
                    {
                        UdpSuccess = true;
                        break;
                    }
                }

                if (!UdpSuccess)
                {
                    Client.Disconnect();
                    Client.onException(new Exception("Handshake went wrong, CHS_UDP"), ErrorType.Core);
                    throw new Exception("The server did not respond in time to acknowledge the UDP connection");
                }
                Client.UdpHandshaked = true;
            }

            Client.MessageHandler.ResetMessages();
            return true;
        }

        private bool onClientUdpHandshake(IMessage message)
        {
            MsgUdpValidation validation = message as MsgUdpValidation;

            if (validation == null)
                return false;

            if (validation.Validation.Length == 5)
            {
                //for now hardcoded values, need to change this soon!
                return validation.Validation[0] == 0x8F && validation.Validation[1] == 0xFF &&
                       validation.Validation[2] == 0x46 && validation.Validation[3] == 0x4F &&
                       validation.Validation[4] == 0x37;
            }
            return false;
        }
    }
}