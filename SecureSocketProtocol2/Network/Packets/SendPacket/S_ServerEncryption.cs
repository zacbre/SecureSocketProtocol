using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Packets.SendPacket
{
    internal class S_ServerEncryption : IWritePacket
    {
        public EncryptionType encryption { get; private set; }
        public CompressionType compression { get; private set; }
        public bool Force { get; private set; }
        public string DiffieKey { get; private set; }

        public S_ServerEncryption(EncryptionType encryption, CompressionType compression, bool Force, string DiffieKey)
        {
            this.encryption = encryption;
            this.compression = compression;
            this.Force = Force;
            this.DiffieKey = DiffieKey;
        }

        public override byte[] WritePayload()
        {
            WriteByte((byte)encryption);
            WriteByte((byte)compression);
            WriteByte(Force ? (byte)1 : (byte)0);
            WriteString(DiffieKey);
            return ToByteArray();
        }
    }
}