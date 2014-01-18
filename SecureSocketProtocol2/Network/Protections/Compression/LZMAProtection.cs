using SecureSocketProtocol2.Compressions.LZMA;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Compression
{
    public class LZMAProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Compression; }
        }

        internal LZMACompressor lzmaCompressor;
        public LZMAProtection()
            : base()
        {
            this.lzmaCompressor = new LZMACompressor();
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            using (MemoryStream outStream = new MemoryStream())
            {
                lzmaCompressor.CompressLZMA(new MemoryStream(data, (int)offset, (int)length), outStream);

                if (outStream.Length < length)
                {
                    packetHeader.isCompressed = true;
                    length = (uint)outStream.Length;
                    return outStream.ToArray();
                }
                return data;
            }
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            if (!packetHeader.isCompressed)
                return data;

            using (MemoryStream outStream = new MemoryStream())
            {
                lzmaCompressor.DecompressLZMA(new MemoryStream(data, (int)offset, (int)length), outStream);
                offset = 0;
                length = (uint)outStream.Length;
                return outStream.ToArray();
            }
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}
