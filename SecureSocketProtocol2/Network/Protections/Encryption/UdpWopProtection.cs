using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Encryption
{
    /// <summary>
    /// WOP is a own written algorithm which is based on performance and being secure, the salt is changing constantly for making it dynamic
    /// </summary>
    public class UdpWopProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Encryption; }
        }

        private WopEncryption wopEncryption;
        public UdpWopProtection()
            : base()
        {
            this.wopEncryption = new WopEncryption(new ulong[] {
                459689754, 201726257, 563084167, 941353141, 431571487,
                973176127, 670574460, 370929887, 135830051, 250211213,
                183548529, 895575941, 760765542, 466725270, 856635237,
                669549115
            },
            new uint[] {
                548280130, 701746305, 273984525, 514010143, 879712086,
                108832561, 861754494, 592727096, 417008568, 558481496,
                220980650, 700261857, 115685594, 842709115, 252951606,
                170641361 
            }, false);
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
