using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgDiffiehellman : IMessage
    {
        public string DiffieHellman;

        public MsgDiffiehellman()
            : base()
        {

        }

        public MsgDiffiehellman(string diffie)
            : base()
        {
            this.DiffieHellman = diffie;
        }
    }
}
