using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Encryption
{
    /// <summary>
    /// AES 256 bit encryption
    /// </summary>
    public class AesProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Encryption; }
        }

        private AesEncryption aes;
        public AesProtection(Connection connection)
            : base()
        {
            this.aes = new AesEncryption(connection, HashAlgorithm.SHA1, 100);
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return aes.Encrypt(ref data, ref offset, ref length);
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            byte[] decrypted = aes.Decrypt(data, ref offset, ref length);
            offset = 0;
            return decrypted;
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}