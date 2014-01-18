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
    }
}