using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    internal class MsgInitPlugin : IMessage
    {
        public ulong PluginId;
        public MsgInitPlugin(ulong PluginId)
            : base()
        {
            this.PluginId = PluginId;
        }
        public MsgInitPlugin()
            : base()
        {

        }
    }
}