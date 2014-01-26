using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    class SHS_TimeSynchronisation : Handshake
    {
        public SHS_TimeSynchronisation(SSPClient client)
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
                    HandshakeType.SendMessage,
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
            Stopwatch TimeSW = Stopwatch.StartNew();
            DateTime TimeNow = DateTime.Now;
            base.SendMessage(new MsgTimeSync(DateTime.Now));

            if (!base.ReceiveMessage((IMessage message) =>
            {
                MsgTimeSyncResponse response = message as MsgTimeSyncResponse;
                if (response != null)
                {
                    TimeSW.Stop();
                    DateTime TimeElapsed = TimeNow.Add(TimeSW.Elapsed);
                    TimeElapsed = TimeElapsed.Subtract(new TimeSpan(0, 0, 0, 0, TimeElapsed.Millisecond));

                    DateTime ResponseTime = DateTime.FromBinary(response.Time);
                    ResponseTime = ResponseTime.Subtract(new TimeSpan(0, 0, 0, 0, ResponseTime.Millisecond));

                    if (ResponseTime > TimeNow.Add(TimeSW.Elapsed))
                    {
                        //something went wrong... shouldn't be possible
                        return false;
                    }
                    else
                    {
                        if (TimeNow.Year != ResponseTime.Year || TimeNow.Month != ResponseTime.Month || TimeNow.Day != ResponseTime.Day ||
                            TimeNow.Hour != ResponseTime.Hour)
                        {
                            return false;
                        }
                        else
                        {
                            //check seconds difference
                            //if it's higher then 10 the connection would be too slow anyway
                            if (TimeNow.Add(TimeSW.Elapsed).Subtract(ResponseTime).Seconds <= 10)
                            {
                                //base.SendMessage(new MsgOk());
                                return true;
                            }
                        }
                    }
                }
                return false;
            }).Wait<bool>(false, 10000))
            {
                Client.Disconnect();
                return false;
            }

            return true;
        }
    }
}
