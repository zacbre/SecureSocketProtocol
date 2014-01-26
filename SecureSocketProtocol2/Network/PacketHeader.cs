using SecureSocketProtocol2.Hashers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class PacketHeader
    {
        public int PacketSize { get; set; }
        public bool isCompressed { get; set; }
        public bool isCached { get; set; }
        public PacketId PacketID { get; set; }
        public uint MessageId { get; set; }
        public ulong PluginId { get; set; }
        public bool isPluginPacket { get; set; }
        public ushort CurPacketId { get; set; }
        public uint Hash { get; set; }
        public uint ChannelId { get; set; }
        private Connection connection;

        public PacketHeader(byte[] header, int offset, Connection connection)
        {
            this.connection = connection;
            PayloadReader pr = new PayloadReader(header);
            pr.Offset += offset;

            PacketSize = pr.ReadThreeByteInteger();
            isCompressed = pr.ReadBool();
            isCached = pr.ReadBool();
            PacketID = (PacketId)pr.ReadByte();
            MessageId = pr.ReadUInteger();
            PluginId = pr.ReadULong();
            isPluginPacket = pr.ReadBool();
            CurPacketId = pr.ReadUShort();
            Hash = pr.ReadUInteger();
            ChannelId = pr.ReadUInteger();
        }

        public PacketHeader(Connection connection)
        {
            this.connection = connection;
        }

        public void WriteHeader(byte[] payload, int offset, int length, NetworkPayloadWriter pw)
        {
            pw.WriteThreeByteInteger(PacketSize);
            pw.WriteBool(isCompressed);
            pw.WriteBool(isCached);
            pw.WriteByte((byte)PacketID);
            pw.WriteUInteger(MessageId);
            pw.WriteULong(PluginId);
            pw.WriteBool(isPluginPacket);
            pw.WriteUShort(CurPacketId);

            if (connection.Client.Certificate != null)
            {
                if (payload != null && length > 0)
                {
                    switch(connection.Client.Certificate.Checksum)
                    {
                        case ChecksumHash.CRC32:
                        {
                            CRC32 hash = new CRC32();
                            this.Hash = BitConverter.ToUInt32(hash.ComputeHash(payload, offset, length), 0);
                            break;
                        }
                    }
                }
            }
            pw.WriteUInteger(Hash);
            pw.WriteUInteger(ChannelId);

            //write protection data, if compressed/cached
            pw.WriteBytes(new byte[connection.protection.LayerCount]);

            //trash data
            pw.WriteBytes(new byte[connection.Client.HeaderTrashCount]);
        }

        public byte[] ToByteArray(Connection connection)
        {
            NetworkPayloadWriter pw = new NetworkPayloadWriter(connection);
            WriteHeader(null, 0, 0, pw);
            return pw.GetPayload();
        }
    }
}