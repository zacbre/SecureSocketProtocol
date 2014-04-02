using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace Client.Messages
{
    public class TestMessage : IPeerMessage
    {
        public byte[] Stuff = new byte[65535];
        public decimal Graf;
        public int PauperGraf;

        public TestMessage()
            : base ()
        {

        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            
        }
    }
}