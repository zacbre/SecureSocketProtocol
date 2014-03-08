using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SecureSocketProtocol2.Encryptions
{
    public class WopEncryption
    {
        internal ulong[] Key_Enc;
        internal uint[] Salt_Enc;
        internal ulong[] Key_Dec;
        internal uint[] Salt_Dec;
        public const uint BLOCK_SIZE = 8;
        public bool UseDynamicKey { get; private set; }
        private Random enc_random = new Random(int.MaxValue/5);
        private Random dec_random = new Random(int.MaxValue/5);

        public readonly ulong[] BbqSauce = new ulong[]
        {
            90954138, 31183745, 33583492, 44605527, 44828674,
            53738919, 55551932, 1374072, 30317181, 47258353,
            17568557, 32166225, 74522482, 10681216, 7946603,
            32644657
        };

        /// <summary>
        /// Initialize Wop Encryption
        /// </summary>
        /// <param name="key">The key/password to use, must be 16 in length</param>
        /// <param name="salt">The Salt to use, must be 16 in length</param>
        /// <param name="UseDynamicKey">Dynamic key will make it harder to decrypt the data, encrypt/decrypt must be done in correct order when used</param>
        public WopEncryption(ulong[] key, uint[] salt, bool UseDynamicKey = true)
        {
            if (key.Length != (BLOCK_SIZE*2) || salt.Length != (BLOCK_SIZE*2))
                throw new Exception("The key and salt size must be " + BLOCK_SIZE*2);

            this.UseDynamicKey = UseDynamicKey;
            this.Key_Enc = new ulong[(BLOCK_SIZE*2)];
            this.Salt_Enc = new uint[(BLOCK_SIZE*2)];
            this.Key_Dec = new ulong[(BLOCK_SIZE*2)];
            this.Salt_Dec = new uint[(BLOCK_SIZE*2)];
            Array.Copy(key, 0, this.Key_Enc, 0, (BLOCK_SIZE*2));
            Array.Copy(key, 0, this.Key_Dec, 0, (BLOCK_SIZE*2));
            Array.Copy(salt, 0, this.Salt_Enc, 0, (BLOCK_SIZE*2));
            Array.Copy(salt, 0, this.Salt_Dec, 0, (BLOCK_SIZE*2));
        }



        public unsafe byte[] Encrypt(byte[] data, int offset, int length)
        {
            if (length == 0)
                return data;
            if (length + offset > data.Length)
                throw new ArgumentException("the offset+length went outside of the data", "offset");
            if (length > data.Length)
                throw new ArgumentException("length is bigger than the data length", "length");

            ulong* prevBlock = (ulong*)0;
            uint blocks = (uint)length / BLOCK_SIZE;
            uint DataLeft = (uint)length % BLOCK_SIZE;

            fixed(void* Block = &(data[offset]), sauce = &(BbqSauce[0]), keyPtr = &(Key_Enc[0]), saltPtr = &(Salt_Enc[0]))
            {
                ulong* CurBlock = (ulong*)Block;
                ulong* saucePtr = (ulong*)sauce;
                for(uint i = 0; i < blocks; i++)
                {
                    CipherBlock(CurBlock, prevBlock, i % BLOCK_SIZE, blocks, saucePtr);
                    prevBlock = CurBlock;
                    CurBlock++;
                }

                byte* bytePtr = (byte*)CurBlock;
                for (; DataLeft > 0; DataLeft--, bytePtr++)
                {
                    byte val = *bytePtr;
                    *bytePtr ^= (byte)Salt_Enc[DataLeft % BLOCK_SIZE];
                    *bytePtr ^= (byte)(Key_Enc[DataLeft % BLOCK_SIZE] << 23 ^ saucePtr[DataLeft % BLOCK_SIZE] ^ 0xDEADBEEF);
                    *bytePtr += (byte)((DataLeft + (DataLeft * DataLeft)) % 0xFF);
                    *bytePtr = RotateRight(*bytePtr);

                    if (UseDynamicKey)
                        Salt_Enc[DataLeft % BLOCK_SIZE] += (uint)((val ^ saucePtr[DataLeft % BLOCK_SIZE]) << 8);
                }
            }
            return data;
        }

        public unsafe byte[] Decrypt(byte[] data, int offset, int length)
        {
            if (length == 0)
                return data;
            if (length + offset > data.Length)
                throw new ArgumentException("the offset+length went outside of the data", "offset");
            if (length > data.Length)
                throw new ArgumentException("length is bigger than the data length", "length");

            ulong* prevBlock = (ulong*)0;
            uint blocks = (uint)length / BLOCK_SIZE;
            uint DataLeft = (uint)length % BLOCK_SIZE;

            fixed(void* Block = &(data[offset]), sauce = &(BbqSauce[0]))
            {
                ulong* CurBlock = (ulong*)Block;
                ulong* saucePtr = (ulong*)sauce;
                for(uint i = 0; i < blocks; i++)
                {
                    DecipherBlock(CurBlock, prevBlock, i % BLOCK_SIZE, blocks, saucePtr);
                    prevBlock = CurBlock;
                    CurBlock++;
                }

                byte* bytePtr = (byte*)CurBlock;
                for(; DataLeft > 0; DataLeft--, bytePtr++)
                {
                    *bytePtr = RotateLeft(*bytePtr);
                    *bytePtr -= (byte)((DataLeft + (DataLeft * DataLeft)) % 0xFF);
                    *bytePtr ^= (byte)(Key_Dec[DataLeft % BLOCK_SIZE] << 23 ^ saucePtr[DataLeft % BLOCK_SIZE] ^ 0xDEADBEEF);
                    *bytePtr ^= (byte)Salt_Dec[DataLeft % BLOCK_SIZE];

                    if (UseDynamicKey)
                        Salt_Dec[DataLeft % BLOCK_SIZE] += (uint)((*bytePtr ^ saucePtr[DataLeft % BLOCK_SIZE]) << 8);
                }
            }
            return data;
        }

        private unsafe void CipherBlock(ulong* Block, ulong* PrevBlock, uint offset, uint BlockCount, ulong* sauce)
        {
            ulong val = *Block;
            *Block ^= Key_Enc[offset] << 23 ^ sauce[offset] ^ 0xDEADBEEF;
            *Block = RotateLeft(*Block, (int)Salt_Enc[offset] >> 59);

            //if(PrevBlock != (ulong*)0)
            //    *Block ^= *PrevBlock;

            *Block += BlockCount + (BlockCount * offset);
            *Block = SwapBits(*Block);

            if (UseDynamicKey)
                Salt_Enc[offset] += (uint)(((val + (ulong)enc_random.Next()) ^ sauce[offset]) << 8);
        }

        private unsafe void DecipherBlock(ulong* Block, ulong* PrevBlock, uint offset, uint BlockCount, ulong* sauce)
        {
            *Block = SwapBits(*Block);
            *Block -= BlockCount + (BlockCount * offset);
            //if(PrevBlock != (ulong*)0)
            //    *Block ^= *PrevBlock;

            *Block = RotateRight(*Block, (int)Salt_Dec[offset] >> 59);
            *Block ^= Key_Dec[offset] << 23 ^ sauce[offset] ^ 0xDEADBEEF;

            if (UseDynamicKey)
                Salt_Dec[offset] += (uint)(((*Block + (ulong)dec_random.Next()) ^ sauce[offset]) << 8);
        }

        private ulong SwapBits(ulong value)
        {
            return ((0x00000000000000FF) & (value >> 56) |
                    (0x000000000000FF00) & (value >> 40) |
                    (0x0000000000FF0000) & (value >> 24) |
                    (0x00000000FF000000) & (value >> 8) | 
                    (0x000000FF00000000) & (value << 8) |
                    (0x0000FF0000000000) & (value << 24) |
                    (0x00FF000000000000) & (value << 40) |
                    (0xFF00000000000000) & (value << 56));
        }

        private ulong RotateLeft(ulong value, int count)
        {
            return (value << count) | (value >> (64 - count));
        }

        private ulong RotateRight(ulong value, int count)
        {
            return (value >> count) | (value << (64 - count));
        }
        
		private byte RotateRight(byte value)
        {
            return (byte)(((value & 1) << 7) | (value >> 1));
        }

        private byte RotateLeft(byte value)
        {
            return (byte)(((value & 0x80) >> 7) | (value << 1));
        }
    }
}