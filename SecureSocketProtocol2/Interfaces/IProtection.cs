using SecureSocketProtocol2.Network;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Interfaces
{
    public abstract class IProtection
    {
        internal bool Enabled { get; set; }
        public abstract ProtectionType Type { get; }

        public IProtection()
        {

        }

        public abstract byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader);
        public abstract byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader);
        public abstract void onApplyPrivateKey(byte[] PrivateKey);

        protected void ApplyPrivateKey(byte[] privateKey, ref byte[] Key)
        {
            long MagicKey = 0;
            for (int i = 0; i < privateKey.Length; i++)
                MagicKey += (privateKey[i] << 1);

            for (int o = 0; o < privateKey.Length; o++)
            {
                Key[o % Key.Length] ^= (byte)(privateKey[o] + MagicKey);
            }
        }
        protected void ApplyPrivateKey(byte[] privateKey, ref uint[] Key)
        {
            long MagicKey = 0;
            for (int i = 0; i < privateKey.Length; i++)
                MagicKey += (privateKey[i] << 1);

            for (int o = 0; o < privateKey.Length; o++)
            {
                Key[o % Key.Length] ^= (uint)(privateKey[o] + MagicKey);
            }
        }
        protected void ApplyPrivateKey(byte[] privateKey, ref ulong[] Key)
        {
            long MagicKey = 0;
            for (int i = 0; i < privateKey.Length; i++)
                MagicKey += (privateKey[i] << 1);

            for (int o = 0; o < privateKey.Length; o++)
            {
                Key[o % Key.Length] ^= (ulong)(privateKey[o] + MagicKey);
            }
        }
    }
}