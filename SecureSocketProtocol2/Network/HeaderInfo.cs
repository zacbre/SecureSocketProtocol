using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    internal class HeaderInfo
    {
        public int PayloadSize { get; private set; }
        public bool isCompressed { get; private set; }
        public PacketId packetId { get; private set; }
        public bool isProcessed { get; internal set; }
        public int DataOffset { get; internal set; }
        public int WriteOffset { get; internal set; }
        public int DataLeftToReceive { get; internal set; }

        public HeaderInfo(ref byte[] headerData, int offset, int DataOffset, Connection connection)
        {
            if (headerData.Length < connection.HEADER_SIZE)
                throw new Exception("Header size is too small");

            this.PayloadSize = (int)headerData[offset] | headerData[offset+1] << 8 | headerData[offset+2] << 16;
            this.isCompressed = headerData[offset+3] == 1;
            this.packetId = (PacketId)headerData[offset+4];
            this.DataOffset = DataOffset;
        }
    }
}