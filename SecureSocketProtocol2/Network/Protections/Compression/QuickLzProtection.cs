using SecureSocketProtocol2.Compressions;
using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Compression
{
    public class QuickLzProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Compression; }
        }

        private UnsafeQuickLZ quickLz; //change to safe or unsafe
        public QuickLzProtection()
            : base()
        {
            this.quickLz = new UnsafeQuickLZ();
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            byte[] compressed = quickLz.compress(data, offset, length);

            if (compressed == null)
            {
                return data;
            }

            if (compressed.Length < length)
            {
                packetHeader.isCompressed = true;
                length = (uint)compressed.Length;
                offset = 0;
                return compressed;
            }
            else
            {
                return data;
            }
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            if (packetHeader.isCompressed)
            {
                byte[] deComressed = quickLz.decompress(data, offset);
                offset = 0;
                length = (uint)deComressed.Length;
                return deComressed;
            }
            return data;
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}