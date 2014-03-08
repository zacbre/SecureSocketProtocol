using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Encryption
{
    /// <summary>
    /// WOP is a own written algorithm which is based on performance and being secure, the salt is changing constantly for making it dynamic
    /// </summary>
    public class TcpWopProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Encryption; }
        }

        private WopEncryption wopEncryption;
        public TcpWopProtection()
            : base()
        {
            this.wopEncryption = new WopEncryption(new ulong[] {
                861335890, 388626021, 404588533, 738562051, 143466081,
                813679996, 890571662, 823294427, 135787739, 421508041,
                841473000, 552393879, 397881016, 459668250, 512708703,
                311855623
            },
            new uint[] {
                921772746, 666327786, 817602825, 400586423, 376646580,
                754874742, 178650796, 973149794, 308786223, 962247449,
                927153850, 989149359, 501229639, 219045145, 331863585,
                318046295, 
            });
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return wopEncryption.Encrypt(data, (int)offset, (int)length);
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return wopEncryption.Decrypt(data, (int)offset, (int)length);
        }


        public override void onApplyPrivateKey(byte[] PrivateKey)
        {
            ApplyPrivateKey(PrivateKey, ref wopEncryption.Key_Dec);
            ApplyPrivateKey(PrivateKey, ref wopEncryption.Key_Enc);
            ApplyPrivateKey(PrivateKey, ref wopEncryption.Salt_Dec);
            ApplyPrivateKey(PrivateKey, ref wopEncryption.Salt_Enc);
        }
    }
}
