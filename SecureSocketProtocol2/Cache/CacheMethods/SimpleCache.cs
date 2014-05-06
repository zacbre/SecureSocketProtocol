using System;
using System.Collections.Generic;
using System.Text;
using SecureSocketProtocol2.Network;
using System.IO;

namespace SecureSocketProtocol2.Cache.CacheMethods
{
    public class SimpleCache : ICache
    {
        private enum CachingType { Equal = 0, NotEqual = 1 };

        public SimpleCache(int CacheSize)
            : base(CacheSize)
        {

        }

        public override string Description
        {
            get { return "A simple cache system where it will check each byte if it's in cache or not"; }
        }

        public override unsafe bool Cache(byte[] Input, int Offset, int Length, MemoryStream Output)
        {
            PayloadWriter pw = new PayloadWriter(Output);

            for (int i = Offset, j = 0; i < Length; )
            {
                int RamCacheIndex = j % base.CacheBuffer.Length;
                int length = MemCmp(Input, i, base.CacheBuffer, RamCacheIndex);

                if (length > 0)
                {
                    CacheInfo inf = new CacheInfo(RamCacheIndex, i, length, true, Instruction.MEMCPY);
                    pw.WriteByte((byte)CachingType.Equal);
                    pw.WriteInteger(length);
                }
                else
                {
                    //first byte in offset wasn't equal
                    //lets scan to see how far it goes
                    length = UnMemCmp(Input, i, base.CacheBuffer, RamCacheIndex);

                    pw.WriteByte((byte)CachingType.NotEqual);
                    pw.WriteInteger(length);
                    pw.WriteBytes(Input, i, length);

                    CacheInfo inf = new CacheInfo(-1, i, length, false, Instruction.NEWDATA);
                    inf.instruction = Instruction.NEWDATA;


                }
                i += length;
                j += length;
            }
            return true;
        }

        public override bool Decache(byte[] Input, int Offset, int Length, MemoryStream Output)
        {
            //PayloadReader pr = new PayloadReader(
            /*while (Output.Position + 5 < Output.Length)
            {

            }*/
            return true;
        }

        private class CacheInfo
        {
            public int CacheIndex;
            public int DataIndex;
            public int Length;
            public bool IsInCache;
            public Instruction instruction;

            public CacheInfo(int CacheIndex, int DataIndex, int Length, bool IsInCache, Instruction instruction)
            {
                this.CacheIndex = CacheIndex;
                this.DataIndex = DataIndex;
                this.Length = Length;
                this.IsInCache = IsInCache;
                this.instruction = instruction;
            }

            public override string ToString()
            {
                return "Data[" + DataIndex + "] -->> Cache[" + CacheIndex + "]";
            }
        }
    }
}