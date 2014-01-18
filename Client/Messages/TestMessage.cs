using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace Client.Messages
{
    public class TestMessage : IMessage
    {
        public byte[] Stuff = new byte[65535];
        public decimal Graf;
        public int PauperGraf;

        public TestMessage()
            : base ()
        {

        }
    }
}