using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Encryption
{
    public class UnsafeXorProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Encryption; }
        }

        private UnsafeXor unsafeXor;
        public UnsafeXorProtection()
            : base()
        {
            this.unsafeXor = new UnsafeXor(true);
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return unsafeXor.Encrypt(ref data, (int)offset, (int)length);
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return unsafeXor.Decrypt(data, (int)offset, (int)length);
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {
            ApplyPrivateKey(PrivateKey, ref unsafeXor.encrypt_key);
            ApplyPrivateKey(PrivateKey, ref unsafeXor.decrypt_key);
        }
    }
}
