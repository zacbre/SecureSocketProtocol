using SecureSocketProtocol2.Hashers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Cache.CacheMethods
{
    public class BufferedCache : ICache
    {
        public enum HashType { CRC32, MD5, SHA1, SimpleFourBytes };

        public uint BlockSize { get; private set; }
        public HashType Hash { get; private set; }
        private SortedList<decimal, byte[]> CacheBuffer;
        private SortedList<decimal, byte[]> deCacheBuffer;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="CacheSize"></param>
        public BufferedCache(int CacheSize, HashType Hash = HashType.SimpleFourBytes)
            : base(CacheSize)
        {
            this.CacheBuffer = new SortedList<decimal, byte[]>();
            this.deCacheBuffer = new SortedList<decimal, byte[]>();
            this.Hash = Hash;
        }

        public override string Description
        {
            get { return "A cache system which will hash your data and look if it's in cache or not"; }
        }

        public override bool Cache(byte[] Input, int Offset, int Length, System.IO.MemoryStream Output)
        {

            return true;
        }

        public override bool Decache(byte[] Input, int Offset, int Length, System.IO.MemoryStream Output)
        {
            return true;
        }


        private decimal HashData(byte[] data, int offset, int length)
        {
            return BitConverter.ToUInt32(data, offset);
            /*switch (Hash)
            {
                case HashType.SimpleFourBytes:
                {
                    return BitConverter.ToUInt32(data, offset);
                }
                case HashType.CRC32:
                {
                    CRC32 hasher = new CRC32();
                    return hasher.ComputeHash(data, offset, length);
                }
                case HashType.MD5:
                {

                    break;
                }
                case HashType.SHA1:
                {

                    break;
                }
            }*/
        }
    }
}