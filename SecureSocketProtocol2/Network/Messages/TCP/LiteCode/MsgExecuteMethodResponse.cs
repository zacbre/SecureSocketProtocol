using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.LiteCode
{
    internal class MsgExecuteMethodResponse : IMessage
    {
        public int RequestId;
        public ReturnResult Result;

        public MsgExecuteMethodResponse(int RequestId, ReturnResult result)
            : base()
        {
            this.RequestId = RequestId;
            this.Result = result;
        }
        public MsgExecuteMethodResponse()
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
                    Client.Connection.Requests[RequestId].Value = Result;
                    Client.Connection.Requests[RequestId].Pulse();
                    Client.Connection.Requests.Remove(RequestId);
                }
            }
            base.ProcessPayload(client, plugin);
        }
    }
}
