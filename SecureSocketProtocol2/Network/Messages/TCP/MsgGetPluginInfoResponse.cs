using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgGetPluginInfoResponse : IMessage
    {
        public string PluginName;
        public string VersionString;

        public MsgGetPluginInfoResponse(string PluginName, string VersionString)
            : base()
        {
            this.PluginName = PluginName;
            this.VersionString = VersionString;
        }
        public MsgGetPluginInfoResponse()
            : base()
        {

        }
    }
}