using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    /// <summary>
    /// This message is being used in the HandShake
    /// </summary>
    internal class MsgServerEncryption : IMessage
    {
        public bool UseUdp;
        public CertInfo certificate;
        public byte[] Key;
        public uint KeyHash;

        public MsgServerEncryption()
            : base()
        {

        }

        public MsgServerEncryption(bool UseUdp, CertInfo certificate, byte[] Key, uint OrgKeyHash)
            : base()
        {
            this.UseUdp = UseUdp;
            this.certificate = certificate;
            this.Key = Key;
            this.KeyHash = OrgKeyHash;
        }
    }
}