using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Plugin
{
    internal class PluginRecvInfo
    {
        public IPlugin Plugin { get; set; }
        public IMessage message { get; set; }
        public byte[] Data { get; set; }

        public PluginRecvInfo(IPlugin Plugin, IMessage message, byte[] Data)
        {
            this.Plugin = Plugin;
            this.message = message;
            this.Data = Data;
        }
    }
}