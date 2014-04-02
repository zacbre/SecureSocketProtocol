using SecureSocketProtocol2.Cache;
using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Cache
{
    public class CacheProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Cache; }
        }

        internal ICache SendCache;
        internal ICache ReceiveCache;
        public CacheProtection(ICache CacheMethod)
            : base()
        {
            this.SendCache = CacheMethod;
            this.ReceiveCache = CacheMethod;
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            using(MemoryStream ms = new MemoryStream())
            {
                SendCache.Cache(data, (int)offset, (int)length, ms);

                data = ms.GetBuffer();
                offset = 0;
                length = (uint)ms.Length;
            }
            packetHeader.isCached = true;
            return data;
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            using (MemoryStream OutStream = new MemoryStream())
            {
                ReceiveCache.Decache(data, (int)offset, (int)length, OutStream);
                data = OutStream.GetBuffer();
                offset = 0;
                length = (uint)OutStream.Length;
            }
            return data;
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}