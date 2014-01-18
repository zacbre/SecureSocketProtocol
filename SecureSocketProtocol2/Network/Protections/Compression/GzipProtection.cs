using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Compression
{
    public class GzipProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Compression; }
        }

        public GzipProtection()
        {

        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return data;
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            if (packetHeader.isCached)
            {
                /*using (MemoryStream outStream = new MemoryStream(data, offset + 3, length - 3))
                {
                    using (GZipStream gs = new GZipStream(outStream, CompressionMode.Decompress))
                    {
                        int DecompressedSize = data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;
                        byte[] decompressed = new byte[DecompressedSize];
                        int readed = gs.Read(decompressed, 0, decompressed.Length);
                        length = decompressed.Length;
                        offset = 0;
                        return decompressed;
                    }
                }*/
            }
            return data;
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}