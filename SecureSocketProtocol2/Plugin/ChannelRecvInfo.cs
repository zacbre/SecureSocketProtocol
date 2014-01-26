using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Plugin
{
    internal class ChannelRecvInfo
    {
        public IMessage Message { get; private set; }
        public uint ChannelId { get; private set; }
        public ChannelRecvInfo(IMessage Message, uint ChannelId)
        {
            this.Message = Message;
            this.ChannelId = ChannelId;
        }
    }
}