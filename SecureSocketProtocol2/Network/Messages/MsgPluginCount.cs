using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    internal class MsgPluginCount : IMessage
    {
        public int PluginCount;
        public MsgPluginCount(int plugins)
            : base()
        {
            this.PluginCount = plugins;
        }
        public MsgPluginCount()
            : base()
        {

        }
    }
}