using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgClientSettings : IMessage
    {
        public bool AllowChannels;
        public bool AllowPeers;

        public MsgClientSettings(bool AllowChannels, bool AllowPeers)
            : base()
        {
            this.AllowChannels = AllowChannels;
            this.AllowPeers = AllowPeers;
        }
        public MsgClientSettings()
            : base()
        {

        }
    }
}