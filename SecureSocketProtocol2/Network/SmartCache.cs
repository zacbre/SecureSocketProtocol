using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class SmartCache : IDisposable
    {
        private byte[] RamCache;
        private FileStream fileStream;
        private uint Size = 65535;
        private int ChunkSize = 2500; //higher = faster but less accurate
        private bool isRam;
        private int IndexWritten = 0;
        private MD5 hasher;
        private List<SmartCacheInfo> HashTable;
        public CacheMode mode { get; private set; }

        /// <summary> Create a new object of Cache, at destroy the cache will be removed </summary>
        /// <param name="RamCache">Store the cache in memory or at disk</param>
        public SmartCache(bool RamCache, uint size, CacheMode mode, int ChunkSize = 2500)
        {
            this.Size = size;
            this.isRam = RamCache;
            this.mode = mode;
            this.ChunkSize = ChunkSize;

            if (RamCache)
            {
                this.RamCache = new byte[Size];
            }
            else
            {
                this.fileStream = new FileStream(Path.GetTempFileName(), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                this.fileStream.Position = Size;
                this.fileStream.WriteByte(0);
                this.fileStream.Lock(0, Size);
            }
            this.hasher = MD5CryptoServiceProvider.Create();
            this.HashTable = new List<SmartCacheInfo>();
        }

        ~SmartCache()
        {
            Dispose();
        }

        public unsafe byte[] Cache(byte[] data, int offset, int length)
        {
            if (isRam)
            {
                PayloadWriter pw = new PayloadWriter();
                if (IndexWritten == 0)
                {
                    pw.WriteInteger(data.Length);
                    pw.WriteByte((byte)Instruction.MEMCPYEX);
                    pw.WriteBytes(data);
                    WriteToCache(data);
                    return pw.ToByteArray();
                }

                //lets see if there is a change
                if (length <= RamCache.Length)
                {
                    fixed (byte* ptr1 = &(data[offset]), ptr2 = RamCache)
                    {
                        if (NativeMethods.memcmp(ptr1, ptr2, (uint)(RamCache.Length > length ? length : RamCache.Length)) == 0)
                        {
                            int len = RamCache.Length > length ? length : RamCache.Length;
                            pw.WriteInteger(len);
                            pw.WriteBytes(writeMEMCPY(len, 0));
                            return pw.ToByteArray();
                        }
                    }
                }

                int DataLength = 0;
                pw.WriteInteger(0); //reserve 4bytes for writing the data length

                FindInCache(data, (SmartCacheInfo inf) =>
                {
                    DataLength += inf.Length;
                    switch (inf.instruction)
                    {
                        case Instruction.NEWDATA:
                        {
                            pw.WriteBytes(WriteNEWDATA(data, inf.DataIndex, inf.Length));
                            break;
                        }
                        case Instruction.MEMCPY:
                        {
                            pw.WriteBytes(writeMEMCPY(inf.Length, inf.CacheIndex));
                            break;
                        }
                    }
                }, mode, offset, length);

                //don't try going above the original data size
                if (pw.Length > length)
                {
                    pw = new PayloadWriter();
                    pw.WriteInteger(DataLength);
                    pw.WriteByte((byte)Instruction.MEMCPYEX);
                    pw.WriteBytes(data);
                    WriteToCache(data);
                    return pw.ToByteArray();
                }
                WriteToCache(data);

                byte[] temp = pw.ToByteArray();
                byte[] lenTemp = BitConverter.GetBytes(DataLength);
                for (int i = 0; i < 4; i++)
                    temp[i] = lenTemp[i];
                return temp;
            }
            return data;
        }

        public unsafe byte[] DeCache(byte[] data, int Offset, int length)
        {
            int DataLength = BitConverter.ToInt32(data, Offset);
            byte[] dest = new byte[DataLength];
            int destPos = 0;
            Offset += 4;

            fixed (byte* destPtr = &(dest[0]), ramPtr = &(RamCache[0]), dataPtr = &(data[0]))
            {
                while (Offset < length)
                {
                    Instruction type = (Instruction)data[Offset];
                    Offset++;
                    switch (type)
                    {
                        case Instruction.MEMCPY:
                        {
                            int size = BitConverter.ToInt32(data, Offset);
                            int offset = BitConverter.ToInt32(data, Offset + 4);
                            NativeMethods.memcpy(destPtr + destPos, ramPtr + offset, (uint)size);
                            Offset += size + 8;
                            destPos += size;
                            //stream.Write(RamCache, offset, size);
                            break;
                        }
                        case Instruction.EJUMP:
                        {
                            //Offset = pr.Packet.Length;
                            break;
                        }
                        case Instruction.MEMCPYEX:
                        {
                            NativeMethods.memcpy(destPtr + destPos, dataPtr + Offset, (uint)(length - Offset));
                            //byte[] temp = pr.ReadBytes(length - pr.Offset);
                            //stream.Write(data, Offset + 1, length - Offset);
                            Offset += length - Offset;
                            destPos += length - Offset;
                            break;
                        }
                        case Instruction.NEWDATA:
                        {
                            int size = BitConverter.ToInt32(data, Offset);
                            NativeMethods.memcpy(destPtr + destPos, dataPtr + Offset, (uint)size);
                            //stream.Write(data, Offset, length - Offset + 4);
                            //stream.Write(pr.ReadBytes(size));
                            Offset += size + 4;
                            destPos += size;
                            break;
                        }
                    }
                }
            }
            WriteToCache(dest);
            return dest;
        }

        private unsafe UInt32 FastRead(void* src, UInt32 bytes)
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
        private unsafe int MemCmp(byte[] data, int offset, byte[] data2, int offset2)
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

        private byte[] writeMEMCPY(int size, int offset)
        {
            List<byte> ret = new List<byte>();
            ret.Add((byte)Instruction.MEMCPY);
            ret.AddRange(BitConverter.GetBytes(size));
            ret.AddRange(BitConverter.GetBytes(offset));
            return ret.ToArray();
        }

        private byte[] WriteNEWDATA(byte[] data, int offset, int length)
        {
            PayloadWriter pw = new PayloadWriter();
            pw.WriteByte((byte)Instruction.NEWDATA);
            pw.WriteInteger(length);
            pw.WriteBytes(data, offset, length);
            return pw.ToByteArray();
        }

        private unsafe void WriteToCache(byte[] data)
        {
            fixed (byte* ptr1 = &(RamCache[0]), ptr2 = &(data[0]))
            {
                NativeMethods.memcpy(ptr1, ptr2, (uint)(RamCache.Length > data.Length ? data.Length : RamCache.Length));
            }

            //Array.Copy(data, RamCache, RamCache.Length > data.Length ? data.Length : RamCache.Length);
            IndexWritten = (data.Length > RamCache.Length) ? RamCache.Length : data.Length;

            //create hash table, currently only being used by type: RandomPosition
            if (mode == CacheMode.RandomPosition)
            {
                HashTable.Clear();
                for (int i = 0; i < RamCache.Length; i += ChunkSize)
                {
                    int length = i + ChunkSize > RamCache.Length ? RamCache.Length - i : ChunkSize;
                    byte[] hashdata = hasher.ComputeHash(RamCache, i, length);
                    BigInteger val = new BigInteger(hashdata);
                    HashTable.Add(new SmartCacheInfo(i, -1, length, true) { CacheValue = val });
                }
            }
        }

        private int HashTableContains(BigInteger value)
        {
            for (int i = 0; i < HashTable.Count; i++)
            {
                if (HashTable[i].CacheValue == value)
                    return i;
            }
            return -1;
        }

        private unsafe void FindInCache(byte[] data, Action<SmartCacheInfo> callback, CacheMode mode, int Offset, int Length)
        {
            if (IndexWritten == 0)
                return;

            switch (mode)
            {
                case CacheMode.SimpleByteScan:
                    {
                        SmartCacheInfo inf = new SmartCacheInfo(0, 0, 0, false);
                        for (int i = Offset, j = 0; i < Length; )
                        {
                            int RamCacheIndex = j % RamCache.Length;
                            int length = MemCmp(data, i, RamCache, RamCacheIndex);

                            if (length > 0)
                            {
                                inf.CacheIndex = RamCacheIndex;
                                inf.DataIndex = i;
                                inf.Length = length;
                                inf.IsInCache = true;
                                inf.instruction = Instruction.MEMCPY;
                                callback(inf);
                            }
                            else
                            {
                                //first byte in offset wasn't equal
                                //lets scan to see how far it goes
                                fixed (byte* ptr1 = data, ptr2 = RamCache)
                                {
                                    for (int o = i; o < Length; o++)
                                    {
                                        if (ptr1[o] != ptr2[o % RamCache.Length])
                                            length++;
                                        else
                                            break;
                                    }
                                }
                                inf.CacheIndex = -1;
                                inf.DataIndex = i;
                                inf.Length = length;
                                inf.IsInCache = false;
                                inf.instruction = Instruction.NEWDATA;
                                callback(inf);
                            }
                            i += length;
                            j += length;
                        }
                        break;
                    }
                case CacheMode.QuickByteScan:
                    {
                        SmartCacheInfo inf = new SmartCacheInfo(0, 0, 0, false);
                        int remaining = Length;
                        for (int i = Offset, j = 0; i < Length; )
                        {
                            int RamCacheIndex = j % RamCache.Length;
                            if (RamCache.Length - RamCacheIndex <= 4)
                                RamCacheIndex = 0;

                            int length = 0;
                            int loops = (RamCache.Length - RamCacheIndex) / 4;
                            int DataLoops = (Length - i) / 4;

                            bool EqualLoop = true;

                            fixed (byte* ptr1 = &(RamCache[RamCacheIndex]), ptr2 = &(data[i]))
                            {
                                uint* RamCachePtr = (uint*)ptr1;
                                uint* DataPtr = (uint*)ptr2;
                                EqualLoop = RamCachePtr[0] == DataPtr[0];
                                for (int o = 0; o < loops && o < DataLoops; o++)
                                {
                                    if (EqualLoop ? RamCachePtr[o] == DataPtr[o] : RamCachePtr[o] != DataPtr[o])
                                        length++;
                                    else
                                        EqualLoop = false;
                                }
                            }

                            if (length > 0)
                            {
                                if (EqualLoop)
                                {
                                    inf.CacheIndex = RamCacheIndex;
                                    inf.DataIndex = i;
                                    inf.Length = length * 4;
                                    inf.IsInCache = true;
                                    inf.instruction = Instruction.MEMCPY;
                                    callback(inf);
                                }
                                else
                                {
                                    inf.CacheIndex = -1;
                                    inf.DataIndex = i;
                                    inf.Length = length * 4;
                                    inf.IsInCache = false;
                                    inf.instruction = Instruction.NEWDATA;
                                    callback(inf);
                                }
                            }
                            else
                            {
                                //no more data
                                break;
                            }

                            remaining -= length * 4;
                            Offset += length * 4;
                            j += length * 4;
                            i += length * 4;
                        }

                        if (remaining > 0)
                        {
                            inf.CacheIndex = -1;
                            inf.DataIndex = Offset;
                            inf.Length = remaining;
                            inf.IsInCache = false;
                            inf.instruction = Instruction.NEWDATA;
                            callback(inf);
                        }
                        break;
                    }
                case CacheMode.RandomPosition:
                    {
                        for (int i = Offset; i < Length; )
                        {
                            int length = i + ChunkSize > Length ? Length - i : ChunkSize;
                            byte[] hashdata = hasher.ComputeHash(data, i, length);
                            BigInteger val = new BigInteger(hashdata);
                            int index = HashTableContains(val);
                            SmartCacheInfo inf = null;

                            if (index == -1)
                            {
                                //keep looking to see what the length is
                                int size = 0;

                                if (length == ChunkSize)
                                {
                                    for (int j = i; j < Length; j += length)
                                    {
                                        length = j + ChunkSize > Length ? Length - j : ChunkSize;
                                        hashdata = hasher.ComputeHash(data, j, length);
                                        val = new BigInteger(hashdata);
                                        if (HashTableContains(val) != -1 || size + length > 65535) //instructions only supports USHORT as size
                                            break;
                                        size += length;
                                    }
                                }
                                else
                                {
                                    size = length;
                                }

                                //int not found, lets see how 
                                inf = new SmartCacheInfo(-1, i, size, false);
                                inf.instruction = Instruction.NEWDATA;
                                callback(inf);
                                i += length;
                            }
                            else
                            {
                                SmartCacheInfo CacheInf = HashTable[index];
                                //WriteDebugInf(data, i, CacheInf.CacheIndex);

                                inf = new SmartCacheInfo(CacheInf.CacheIndex, i, 0, true); //0 index for now just see what the length is of the MemCmp
                                inf.Length = MemCmp(data, i, RamCache, CacheInf.CacheIndex);
                                callback(inf);
                            }
                            i += inf.Length;
                        }
                        break;
                    }
            }
        }

        public void Dispose()
        {
            if (fileStream != null)
            {
                string filePath = fileStream.Name;
                fileStream.Close();
                File.Delete(filePath);
            }
            RamCache = null;
        }
    }
}