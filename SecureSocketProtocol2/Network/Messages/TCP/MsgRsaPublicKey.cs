using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgRsaPublicKey : IMessage
    {
        public string PublicKey;
        public MsgRsaPublicKey(string PublicKey)
            : base()
        {
            this.PublicKey = PublicKey;
        }
        public MsgRsaPublicKey()
            : base()
        {

        }
    }
}