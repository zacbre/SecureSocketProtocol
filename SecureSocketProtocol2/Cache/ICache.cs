using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace SecureSocketProtocol2.Cache
{
    public abstract class ICache
    {
        protected byte[] CacheBuffer { get; private set; }
        protected byte[] DecacheBuffer { get; private set; }


        public abstract string Description { get; }
        public abstract bool Cache(byte[] Input, int Offset, int Length, MemoryStream Output);
        public abstract bool Decache(byte[] Input, int Offset, int Length, MemoryStream Output);

        public ICache(int CacheSize)
        {
            this.CacheBuffer = new byte[CacheSize];
            this.DecacheBuffer = new byte[CacheSize];
        }

        protected unsafe UInt32 FastRead(void* src, UInt32 bytes)
        {
            UInt32 val = 0;
            if (BitConverter.IsLittleEndian)
                val = *((UInt32*)src);
            else
            {
                Byte* p = (Byte*)src;
                switch (bytes)
                {
                    case 4:
                        val = (UInt32)(*p) | (UInt32)(*(p + 1)) << 8 | (UInt32)(*(p + 2)) << 16 | (UInt32)(*(p + 3)) << 24;
                        break;
                    case 3:
                        val = (UInt32)(*p) | (UInt32)(*(p + 1)) << 8 | (UInt32)(*(p + 2)) << 16;
                        break;
                    case 2:
                        val = (UInt32)(*p) | (UInt32)(*(p + 1)) << 8;
                        break;
                    case 1:
                        val = (UInt32)(*p);
                        break;
                    default: break;
                }
            }
            return val;
        }

        /// <summary> Compare 2 byte arrays </summary>
        /// <returns>The length of being equal</returns>
        protected unsafe int MemCmp(byte[] data, int offset, byte[] data2, int offset2)
        {
            int equalLength = 0;
            fixed (byte* ptr1 = data, ptr2 = data2)
            {
                for (; offset < data.Length && offset2 < data2.Length; offset++, offset2++)
                {
                    if (ptr1[offset] != ptr2[offset2])
                        return equalLength;
                    equalLength++;
                }
            }
            return equalLength;
        }

        /// <summary> Compare 2 byte arrays </summary>
        /// <returns>The length of being not equal</returns>
        protected unsafe int UnMemCmp(byte[] data, int offset, byte[] data2, int offset2)
        {
            int equalLength = 0;
            fixed (byte* ptr1 = data, ptr2 = data2)
            {
                for (; offset < data.Length && offset2 < data2.Length; offset++, offset2++)
                {
                    if (ptr1[offset] != ptr2[offset2])
                    {
                        equalLength++;
                        continue;
                    }
                    return equalLength;
                }
            }
            return equalLength;
        }
    }
}