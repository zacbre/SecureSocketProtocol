using SevenZip.Compression.LZMA;
using System;
using System.Collections.Generic;
using System.IO;

namespace SecureSocketProtocol2.Compressions.LZMA
{
    public class LZMACompressor
    {
        private Encoder encoder = new Encoder();
        private Decoder decoder = new Decoder();
        public LZMACompressor()
        {
            this.encoder = new Encoder();
            this.decoder = new Decoder();
        }

        public void CompressLZMA(MemoryStream input, MemoryStream output)
        {
            lock (encoder)
            {
                encoder.WriteCoderProperties(output);
                output.Write(BitConverter.GetBytes(input.Length), 0, 8);
                encoder.Code(input, output, input.Length, -1, null);
                output.Flush();
            }
        }

        public void DecompressLZMA(MemoryStream input, MemoryStream output)
        {
            lock (decoder)
            {
                byte[] properties = new byte[5];
                input.Read(properties, 0, 5);

                byte[] fileLengthBytes = new byte[8];
                input.Read(fileLengthBytes, 0, 8);
                long fileLength = BitConverter.ToInt64(fileLengthBytes, 0);

                decoder.SetDecoderProperties(properties);
                decoder.Code(input, output, input.Length, fileLength, null);
                output.Flush();
            }
        }
    }
}
