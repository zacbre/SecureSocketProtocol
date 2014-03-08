using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace Server.Messages
{
    public class TestMessage : IMessage
    {
        public byte[] Stuff = new byte[256];
        public decimal Graf;
        public int PauperGraf;
        public TestMessage()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, SecureSocketProtocol2.Plugin.IPlugin plugin = null)
        {
            base.ProcessPayload(client, plugin);
        }
    }
}