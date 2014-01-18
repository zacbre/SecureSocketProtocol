using SecureSocketProtocol2.Compressions.LZ4;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Compression
{
    public class LZ4Protection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Compression; }
        }

        internal ILZ4Compressor Lz4Compressor;
        internal ILZ4Decompressor Lz4Decompressor;
        public LZ4Protection()
            : base()
        {
            this.Lz4Compressor = new LZ4Compressor32();
            this.Lz4Decompressor = new LZ4Decompressor32();
        }

        /// <summary>
        /// Compresses the data
        /// </summary>
        /// <param name="data">The data to compress</param>
        /// <param name="offset">The position where the data begins</param>
        /// <param name="length">The length to compress</param>
        /// <returns></returns>
        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            byte[] compressed = new byte[Lz4Compressor.CalculateMaxCompressedLength((int)length)];
            int CompressedSize = Lz4Compressor.Compress(data, (int)offset, (int)length, compressed, 0);

            if (CompressedSize < length)
            {
                offset = 0;
                length = (uint)CompressedSize;
                return compressed;
            }
            return data;
        }

        /// <summary>
        /// Decompress the data, Offset and Length cannot be used
        /// </summary>
        /// <param name="data">The data to decompress</param>
        /// <param name="offset">CANNOT BE USED</param>
        /// <param name="length">CANNOT BE USED</param>
        /// <returns></returns>
        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            if (packetHeader.isCompressed)
            {
                byte[] deCompressed = Lz4Decompressor.Decompress(data);
                offset = 0;
                length = (uint)deCompressed.Length;
                return deCompressed;
            }
            return data;
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}