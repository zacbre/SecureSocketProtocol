using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    internal class MsgGetPluginInfo : IMessage
    {
        public ulong PluginId;

        public MsgGetPluginInfo(ulong PluginId)
            : base()
        {
            this.PluginId = PluginId;
        }
        public MsgGetPluginInfo()
            : base()
        {

        }
    }
}