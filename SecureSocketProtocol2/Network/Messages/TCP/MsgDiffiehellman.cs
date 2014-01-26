using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgDiffiehellman : IMessage
    {
        public byte[] DiffieHellman;

        public MsgDiffiehellman()
            : base()
        {

        }

        public MsgDiffiehellman(byte[] diffie)
            : base()
        {
            this.DiffieHellman = diffie;
        }
    }
}
