using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_TimeSynchronisation : Handshake
    {
        public CHS_TimeSynchronisation(SSPClient client)
            : base(client)
        {

        }

        public override HandshakeType[] ServerTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.SendMessage,
                    HandshakeType.ReceiveMessage,
                };
            }
        }

        public override HandshakeType[] ClientTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.ReceiveMessage,
                    HandshakeType.SendMessage,
                };
            }
        }

        public override bool onHandshake()
        {
            SyncObject syncObject = null;
            if (!(syncObject = base.ReceiveMessage((IMessage message) =>
            {
                MsgTimeSync time = message as MsgTimeSync;

                if (time != null)
                {
                    Client._timeSync = DateTime.FromBinary(time.Time);
                    Client.TimeSyncSW = Stopwatch.StartNew();
                    base.SendMessage(new MsgTimeSyncResponse(Client.TimeSync.ToBinary()));
                    return true;
                }
                return false;
            })).Wait<bool>(false, 15000))
            {
                Client.Disconnect(DisconnectReason.TimeOut);
                Client.onException(new Exception("Handshake went wrong, CHS_TimeSynchronisation"), ErrorType.Core);
                if (syncObject.TimedOut)
                    throw new TimeoutException(TimeOutMessage);
                throw new Exception("Failed to synchronize the time with the server");
            }
            return true;
        }
    }
}