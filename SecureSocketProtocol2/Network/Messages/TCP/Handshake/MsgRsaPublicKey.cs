using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgRsaPublicKey : IMessage
    {
        public byte[] Modulus;
        public byte[] Exponent;
        public MsgRsaPublicKey(RSAParameters Parameters)
            : base()
        {
            this.Modulus = Parameters.Modulus;
            this.Exponent = Parameters.Exponent;
        }
        public MsgRsaPublicKey()
            : base()
        {

        }
    }
}