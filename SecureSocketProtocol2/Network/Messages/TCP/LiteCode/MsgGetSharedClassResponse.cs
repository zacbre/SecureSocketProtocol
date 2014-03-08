using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.LiteCode
{
    internal class MsgGetSharedClassResponse : IMessage
    {
        public ReturnResult Result;
        public int RequestId;

        public MsgGetSharedClassResponse(int RequestId, ReturnResult Result)
            : base()
        {
            this.RequestId = RequestId;
            this.Result = Result;
        }
        public MsgGetSharedClassResponse()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            SSPClient Client = client as SSPClient;
            lock (Client.Connection.Requests)
            {
                if (Client.Connection.Requests.ContainsKey(RequestId))
                {
                    //Console.WriteLine("result is null ? " + (Result == null));
                    Client.Connection.Requests[RequestId].Value = Result;
                    Client.Connection.Requests[RequestId].Pulse();
                    Client.Connection.Requests.Remove(RequestId);
                }
            }
            base.ProcessPayload(client);
        }
    }
}
