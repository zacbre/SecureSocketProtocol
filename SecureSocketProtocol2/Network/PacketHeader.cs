using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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
        public uint PeerId { get; set; }

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
            PeerId = pr.ReadUInteger();
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

            if (connection.Client.Certificate != null && connection.Client.Handshaked)
            {
                Hash = HashPayload(payload, offset, length, connection.Client.Certificate.Checksum);
            }
            else
            {
                //No certificate yet, always hash with SHA512
                Hash = HashPayload(payload, offset, length, Connection.HandshakeChecksum);
            }

            pw.WriteUInteger(Hash);
            pw.WriteUInteger(ChannelId);
            pw.WriteUInteger(PeerId);

            //trash data
            byte[] tempJumk = new byte[connection.Client.HeaderJunkCount];
            new Random().NextBytes(tempJumk);
            pw.WriteBytes(tempJumk);
        }

        public byte[] ToByteArray(Connection connection)
        {
            NetworkPayloadWriter pw = new NetworkPayloadWriter(connection);
            WriteHeader(null, 0, 0, pw);
            return pw.GetPayload();
        }

        internal uint HashPayload(byte[] payload, int offset, int length, ChecksumHash HashType)
        {
            if (HashType == ChecksumHash.None)
                return 0;

            uint hash = 0;

            BigInteger BigTemp = new BigInteger();
            if (payload != null && length > 0)
            {
                if (ChecksumHash.CRC32 == (HashType & ChecksumHash.CRC32))
                {
                    using (CRC32 hasher = new CRC32())
                    {
                        BigTemp += new BigInteger(hasher.ComputeHash(payload, offset, length));
                    }
                }
                if (ChecksumHash.MD5 == (HashType & ChecksumHash.MD5))
                {
                    using (MD5 hasher = MD5.Create())
                    {
                        BigTemp += new BigInteger(hasher.ComputeHash(payload, offset, length));
                    }
                }
                if (ChecksumHash.SHA1 == (HashType & ChecksumHash.SHA1))
                {
                    using (SHA1 hasher = SHA1.Create())
                    {
                        BigTemp += new BigInteger(hasher.ComputeHash(payload, offset, length));
                    }
                }
                if (ChecksumHash.SHA512 == (HashType & ChecksumHash.SHA512))
                {
                    using (SHA512 hasher = SHA512.Create())
                    {
                        BigTemp += new BigInteger(hasher.ComputeHash(payload, offset, length));
                    }
                }
            }

            //here is the point where the collisions could begin!
            //Xor, Mod, later to fix it, for now let's leave it like this
            do
            {
                hash += (uint)BigTemp.LongValue();
                BigTemp >>= 32;
            }
            while (BigTemp > 0);
            return hash;
        }
    }
}