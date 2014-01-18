using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Cache
{
    public class SmartCacheProtection : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Cache; }
        }

        internal SmartCache TargetCache;
        internal SmartCache ReceiveCache;
        public SmartCacheProtection()
            : base()
        {
            this.TargetCache = new SmartCache(true, Connection.MAX_CACHE_SIZE, CacheMode.SimpleByteScan, 2500);
            this.ReceiveCache = new SmartCache(true, Connection.MAX_CACHE_SIZE, CacheMode.SimpleByteScan, 2500);
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return null;
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            return null;
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}