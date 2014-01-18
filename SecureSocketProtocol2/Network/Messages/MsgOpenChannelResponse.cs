﻿using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    internal class MsgOpenChannelResponse : IMessage
    {
        public ulong ConnectionId;
        public bool success;

        public MsgOpenChannelResponse()
            : base()
        {

        }

        public MsgOpenChannelResponse(ulong connectionId, bool success)
            : base()
        {
            this.ConnectionId = connectionId;
            this.success = success;
        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            client.Connection.Client.ChannelSyncObject.Value = this;
            client.Connection.Client.ChannelSyncObject.Pulse();
            base.ProcessPayload(client);
        }
    }
}