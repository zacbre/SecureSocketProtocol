using SecureSocketProtocol2.Network;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SecureSocketProtocol2.Compressions
{
    public class CacheStream
    {
        private List<CacheInfo>[] cache;
        internal const int CacheSize = 4096;
        public const int MaxMemoryUsage = 1000000;
        public const int CacheTimeToLife = 10; //cache can live 10 seconds
        private int CacheInfoSize = 12;
        private Connection connection;

        public int UsedMemory
        {
            get;
            private set;
        }

        private enum CacheType
        {
            NewData = 0,
            ReadFromCacheSmall = 1,
            ReadFromCacheBig = 3,
        }

        public CacheStream(Connection connection)
            : base()
        {
            cache = new List<CacheInfo>[CacheSize];
            for (int i = 0; i < cache.Length; i++)
                cache[i] = new List<CacheInfo>();
            this.connection = connection;
        }

        public void Flush()
        {
            if (UsedMemory > MaxMemoryUsage)
            {
                int cleaned = 0;
                for (int i = 0; i < cache.Length; i++)
                {
                    for (int j = cache[i].Count - 1; j > 0; j--)
                    {
                        if (cache[i][j].TTL.Elapsed.Seconds > CacheTimeToLife || cache[i][j].UseCount == 1)
                        {
                            cache[i].Remove(cache[i][j]);
                            cleaned++;
                        }
                    }
                }
            }
        }

        public unsafe int Read(byte[] buffer, int offset, uint count, ref byte[] Data)
        {
            if (count < 4)
                return 0;

            uint CacheLength = BitConverter.ToUInt32(buffer, offset);
            Data = new byte[CacheLength];

            fixed (byte* Ptr1 = &(buffer[connection.HEADER_SIZE+offset+4]), Ptr2 = &(Data[0]))
            {
                byte* DataPtr = Ptr2;
                byte* BufferPtr = Ptr1;

                while(count > 0)
                {
                    switch ((CacheType)BufferPtr[0])
                    {
                        case CacheType.NewData:
                        {
                            CacheInfo info = new CacheInfo((uint*)BufferPtr + 1);
                            cache[info.CacheIndex].Add(info);
                            *(uint*)DataPtr = info.Hash;
                            BufferPtr += 5;
                            break;
                        }
                        case CacheType.ReadFromCacheBig:
                        {

                            break;
                        }
                        case CacheType.ReadFromCacheSmall:
                        {
                            int index = BufferPtr[1];
                            int ListIndex = BufferPtr[2];

                            if (cache[index].Count < ListIndex)
                            {
                                CacheInfo info = cache[index][ListIndex];
                                *(uint*)DataPtr = info.Hash;
                            }
                            BufferPtr += 3;
                            break;
                        }
                    }
                    count -= 4;
                    DataPtr += 4;
                }
            }
            return 0;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="npw">The input data</param>
        /// <param name="Data">The data that is being cached</param>
        /// <returns>Is data cached</returns>
        public unsafe uint Write(NetworkPayloadWriter npw, ref byte[] Data)
        {
            byte[] payload = npw.GetBuffer();
            uint UsedBytes = (uint)connection.HEADER_SIZE;
            Data = new byte[payload.Length + 5000]; //+5kb space
            Array.Copy(payload, Data, connection.HEADER_SIZE); //copy SSP header

            int length = (npw.Length - connection.HEADER_SIZE);
            int loops = (int)Math.Ceiling((double)length / 4D);

            fixed (byte* tempPtr = &(payload[connection.HEADER_SIZE]), dataPtr = &(Data[connection.HEADER_SIZE + 4]))
            {
                if ((npw.Length - connection.HEADER_SIZE) > 0)
                {
                    uint* payloadPtr = (uint*)tempPtr;
                    byte* DataPtr = (byte*)dataPtr;
                    for (int i = 0; i < loops; i++)
                    {
                        if (UsedBytes > payload.Length)
                        {
                            //stop caching
                            Flush();
                            return 0;
                        }

                        CacheInfo info = new CacheInfo(payloadPtr);
                        CacheInfo temp = null;
                        int ListIndex = 0;
                        if (TryGetCacheInfo(ref temp, info.Hash, ref ListIndex))
                        {
                            //read from cache
                            temp.UseCount++;

                            //check index size for write
                            if (info.CacheIndex > 254)
                            {
                                UsedBytes += 3;
                                *DataPtr = (byte)CacheType.ReadFromCacheBig;
                                DataPtr[1] = (byte)info.CacheIndex;
                                DataPtr[2] = (byte)(info.CacheIndex >> 8);
                                DataPtr += 3;
                            }
                            else
                            {
                                UsedBytes += 3;
                                *DataPtr = (byte)CacheType.ReadFromCacheSmall;
                                DataPtr[1] = (byte)info.CacheIndex;
                                DataPtr[2] = (byte)ListIndex;
                                DataPtr += 3;
                            }
                        }
                        else
                        {
                            //new data
                            info.UseCount = 1;
                            UsedBytes += 5;
                            cache[info.CacheIndex].Add(info);
                            *DataPtr = (byte)CacheType.NewData;
                            *(uint*)(DataPtr + 1) = info.Hash;
                            UsedMemory += CacheInfoSize;
                            DataPtr += 5;
                        }
                        payloadPtr++;
                    }
                }
                *(uint*)(dataPtr - 4) = (uint)(npw.Length - connection.HEADER_SIZE);
            }
            Flush();
            return UsedBytes;
        }

        private bool TryGetCacheInfo(ref CacheInfo info, uint hash, ref int Index)
        {
            int index = HashToIndex(hash);
            for (int j = 0; j < cache[index].Count; j++)
            {
                if (cache[index][j].Hash == hash)
                {
                    info = cache[index][j];
                    Index = j;
                    return true;
                }
            }
            return false;
        }

        internal int HashToIndex(uint Hash)
        {
            return (int)Hash & (CacheSize - 1);
        }

        #region Nested Classes
        private unsafe class CacheInfo
        {
            public Stopwatch TTL;
            public uint Hash;
            public uint CacheIndex { get { return Hash % CacheSize; } }

            /// <summary>
            /// A counter which shows how many times this cache chunk is being used
            /// </summary>
            public uint UseCount;

            public CacheInfo(uint* hash)
            {
                TTL = Stopwatch.StartNew();
                this.Hash = *hash;
            }
        }
        #endregion
    }
}