using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class SmartCacheInfo
    {
        public int CacheIndex;
        public int DataIndex;
        public int Length;
        public bool IsInCache;
        internal Instruction instruction;
        public BigInteger CacheValue;

        public SmartCacheInfo(int CacheIndex, int DataIndex, int Length, bool IsInCache)
        {
            this.CacheIndex = CacheIndex;
            this.DataIndex = DataIndex;
            this.Length = Length;
            this.IsInCache = IsInCache;
            this.instruction = Instruction.MEMCPY;
        }

        public override string ToString()
        {
            return "Data[" + DataIndex + "] -->> Cache[" + CacheIndex + "]";
        }
    }
}
